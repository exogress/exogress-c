#include "../exogress.h"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
//
//void cb(uint8_t const* peer_id, uint8_t const* ptr, uintptr_t len)
//{
//    fprintf(stderr, "WRAPPER| Received message\n");
//}
//
//void log_stderr(LogLevel level, const c_char *msg)
//{
//    fprintf(stderr, "FOREIGN = %s\n", msg);
//}

void *spawn()
{
    exogress_instance_spawn(1);
    return NULL;
}

int main()
{
    fprintf(stderr, "VERSION = %s\n", exogress_version());
    fprintf(stderr, "WRAPPER| Spawn exogress client\n");
//    // trunk_init_logger(LogLevel_INFO);
    InstanceId instance1 = exogress_instance_init(
            "01F68JEA8XW0MM1XGGR47F7KSD",
            "a83Xj28xao6UkHRasZUhVVrrhc26w8RMJsyV7kkgn7jU",
            "glebpom",
            "location-tester"
    );

    if (instance1 < 1) {
        fprintf(stderr, "RET =  %d\n", instance1);

    }

    exogress_instance_add_label(instance1, "label1", "value1");
    exogress_instance_add_label(instance1, "label2", "value2");
    exogress_instance_set_watch_config(instance1, true);

    pthread_t spawn_thread;

    pthread_create(&spawn_thread, NULL, spawn, NULL);
    sleep(100);
    exogress_instance_stop(instance1);
}