use core::mem;
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    sync::Arc,
};

use anyhow::bail;
use exogress_common::{
    client_core::Client,
    entities::{AccessKeyId, AccountName, LabelName, LabelValue, ProjectName, SmolStr},
};
use futures::channel::{
    mpsc,
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};
use hashbrown::{hash_map::Entry, HashMap};
use lazy_static::lazy_static;
use log::{info, Level, LevelFilter, Metadata, Record};
use parking_lot::{Once, RwLock};
use tokio::runtime::Runtime;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Once = Once::new();

enum InstanceState {
    Initialized(InstanceConfig),
    Spawned(Instance),
    Stopped,
}

struct SpawnInfo {
    client: Client,
    reload_config_tx: UnboundedSender<()>,
    reload_config_rx: UnboundedReceiver<()>,
    stop_rx: oneshot::Receiver<()>,
}

impl InstanceState {
    fn switch_to_spawned(&mut self) -> anyhow::Result<SpawnInfo> {
        let cfg = match self {
            InstanceState::Initialized(cfg) => cfg,
            InstanceState::Spawned(_) => {
                bail!("already spawned")
            }
            InstanceState::Stopped => {
                bail!("already stopped")
            }
        };

        let spawned = InstanceState::Spawned(Instance {
            reload_config_tx: cfg.reload_config_tx.clone(),
            stop_tx: Some(cfg.stop_tx.take().expect("TODO")),
        });

        let old = mem::replace(self, spawned);

        match old {
            InstanceState::Initialized(cfg) => Ok(SpawnInfo {
                client: cfg.client_builder.build()?,
                reload_config_tx: cfg.reload_config_tx.clone(),
                reload_config_rx: cfg.reload_config_rx,
                stop_rx: cfg.stop_rx,
            }),
            _ => unreachable!(),
        }
    }
}

pub struct InstanceConfig {
    client_builder: exogress_common::client_core::ClientBuilder,
    reload_config_tx: UnboundedSender<()>,
    reload_config_rx: UnboundedReceiver<()>,
    stop_tx: Option<oneshot::Sender<()>>,
    stop_rx: oneshot::Receiver<()>,
}

pub struct Instance {
    reload_config_tx: UnboundedSender<()>,
    stop_tx: Option<oneshot::Sender<()>>,
}

#[derive(Default)]
struct Storage {
    map: HashMap<InstanceId, InstanceState>,
    last_id: InstanceId,
}

impl Storage {
    fn new_instance_id(&mut self) -> InstanceId {
        self.last_id += 1;
        self.last_id
    }
}

pub type InstanceId = u32;

lazy_static! {
    static ref STORAGE: Arc<RwLock<Storage>> = Arc::new(RwLock::new(Default::default()));
    static ref EXOGRESS_VERSION: CString =
        CString::new(exogress_common::client_core::VERSION).unwrap();
}

macro_rules! parse_c_str {
    ($var:ident) => {
        match CStr::from_ptr($var).to_str() {
            Ok(s) => match s.parse() {
                Ok(entity) => entity,
                Err(_e) => {
                    todo!()
                }
            },
            Err(_e) => {
                todo!();
            }
        }
    };
}
macro_rules! read_string {
    ($var:ident) => {
        match CStr::from_ptr($var).to_str() {
            Ok(s) => s.to_string(),
            Err(_e) => {
                todo!();
            }
        }
    };
}

#[no_mangle]
///
/// Returns a pointer to C string with Exogress version.
/// Should be equal to `EXOGRESS_HEADER_VERSION`
///
pub extern "C" fn exogress_version() -> *const c_char {
    EXOGRESS_VERSION.as_ptr()
}

///
/// Call this function once per the instance at the beginning.
///
/// # Safety
///
/// This function should passed pointer to valid C strings.
#[no_mangle]
pub unsafe extern "C" fn exogress_instance_init(
    access_key_id: *mut c_char,
    secret_access_key: *mut c_char,
    account: *mut c_char,
    project: *mut c_char,
) -> i64 {
    LOGGER.call_once(|| {
        log::set_boxed_logger(Box::new(SimpleLogger))
            .map(|()| log::set_max_level(LevelFilter::Info))
            .unwrap();
    });

    let access_key_id: AccessKeyId = parse_c_str!(access_key_id);
    let secret_access_key: String = match CStr::from_ptr(secret_access_key).to_str() {
        Ok(s) => s.to_string(),
        Err(_e) => {
            todo!();
        }
    };
    let account: AccountName = parse_c_str!(account);
    let project: ProjectName = parse_c_str!(project);

    let mut storage = STORAGE.write();
    let instance_id = storage.new_instance_id();

    let mut client_builder = Client::builder();

    // if let Some(config_path) = maybe_config_path {
    //     client_builder.config_path(config_path);
    // }

    client_builder
        .access_key_id(access_key_id)
        .secret_access_key(secret_access_key)
        .account(account)
        .project(project)
        // .watch_config(watch_config)
        // .profile(None)
        // .labels(labels)
        .additional_connection_params({
            let mut map = HashMap::<SmolStr, SmolStr>::new();
            map.insert("client".into(), "c".into());
            map.insert("wrapper_version".into(), CRATE_VERSION.into());
            map
        });

    let (reload_config_tx, reload_config_rx) = mpsc::unbounded();
    let (stop_tx, stop_rx) = oneshot::channel();

    let data = InstanceState::Initialized(InstanceConfig {
        client_builder,
        reload_config_tx,
        reload_config_rx,
        stop_tx: Some(stop_tx),
        stop_rx,
    });

    storage.map.insert(instance_id, data);
    instance_id.into()
}

#[no_mangle]
///
/// Add a label to exogress instance. Should be called before spawning
///
/// # Safety
///
/// This function should passed pointer to valid C strings.
pub unsafe extern "C" fn exogress_instance_add_label(
    instance_id: InstanceId,
    name: *const c_char,
    value: *const c_char,
) {
    let mut h = STORAGE.write();
    if let Some(&mut InstanceState::Initialized(ref mut cfg)) = h.map.get_mut(&instance_id) {
        let name: LabelName = parse_c_str!(name);
        let value: LabelValue = parse_c_str!(value);

        cfg.client_builder.label(name, value);
    }
}

#[no_mangle]
///
/// Set config path to exogress instance. Should be called before spawning
///
/// # Safety
///
/// This function should passed pointer to valid C strings.
pub unsafe extern "C" fn exogress_instance_set_config_path(
    instance_id: InstanceId,
    path: *const c_char,
) {
    let mut h = STORAGE.write();
    if let Some(&mut InstanceState::Initialized(ref mut cfg)) = h.map.get_mut(&instance_id) {
        let path = read_string!(path);

        cfg.client_builder.config_path(path);
    }
}

#[no_mangle]
///
/// Set config path to exogress instance. Should be called before spawning
///
pub extern "C" fn exogress_instance_set_watch_config(instance_id: InstanceId, should_watch: bool) {
    let mut h = STORAGE.write();
    if let Some(&mut InstanceState::Initialized(ref mut cfg)) = h.map.get_mut(&instance_id) {
        cfg.client_builder.watch_config(should_watch);
    }
}

///
/// Spawn Exogress instance. This function will be blocked until instance is terminated.
/// The wrapper should run it inside a thread
///
#[no_mangle]
pub extern "C" fn exogress_instance_spawn(instance_id: InstanceId) {
    let mut h = STORAGE.write();
    let entry = h.map.entry(instance_id);
    let SpawnInfo {
        client,
        reload_config_tx,
        reload_config_rx,
        stop_rx,
    } = match entry {
        Entry::Occupied(mut occupied) => {
            let value = occupied.get_mut();
            match value {
                InstanceState::Initialized(_) => {
                    // go ahead
                }
                InstanceState::Spawned(_) => {
                    todo!("already spawned")
                }
                InstanceState::Stopped => {
                    todo!("stopped")
                }
            }

            value.switch_to_spawned().expect("TODO")
        }
        Entry::Vacant(_) => {
            todo!("not found");
        }
    };

    // release lock
    mem::drop(h);

    let rt = Runtime::new().expect("TODO");

    let resolver = TokioAsyncResolver::from_system_conf(TokioHandle).expect("TODO");

    rt.block_on(async move {
        let spawn = client.spawn(reload_config_tx, reload_config_rx, resolver);

        tokio::select! {
            r = spawn => {
                if let Err(e) = r {
                    info!("error: {}", e);
                    todo!();
                }
            },
            _ = stop_rx => {
                info!("stop exogress instance by request");
            }
        }

        Ok::<_, anyhow::Error>(())
    })
    .expect("TODO");

    STORAGE
        .write()
        .map
        .entry(instance_id)
        .and_modify(|instance| *instance = InstanceState::Stopped);
}

#[no_mangle]
///
/// Stop the instance. This leads to the immediate interruption of the instance if it is in a running state.
/// After stopping the instance, it may not be used or spawned again later.
/// The thread will be blocked until instance stops.
///
pub extern "C" fn exogress_instance_stop(instance_id: InstanceId) {
    let mut h = STORAGE.write();

    if let Some(InstanceState::Spawned(spawned)) = h.map.get_mut(&instance_id) {
        if let Some(stop_tx) = spawned.stop_tx.take() {
            let _ = stop_tx.send(());
        }
    }
}

#[no_mangle]
///
/// Reload the instance.
///
pub extern "C" fn exogress_instance_reload(instance_id: InstanceId) {
    let h = STORAGE.read();

    if let Some(InstanceState::Spawned(spawned)) = h.map.get(&instance_id) {
        let _ = spawned.reload_config_tx.unbounded_send(());
    }
}
