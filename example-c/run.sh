#!/usr/bin/env bash
#https://github.com/rust-lang/rust/blob/master/src/test/run-make/tools.mk#L68

gcc main.c ../target/debug/libexogress.a -o wrapper -lresolv -framework Security -framework Foundation -Dc_char="char" -Dc_void="void" -Dc_int="int"  && ./wrapper
#gcc main.c ../target/release/libtrunk.a -o wrapper -lresolv -framework Security -framework Foundation -Dc_char="char" && ./wrapper
# gcc main.c ../cross/osx/libs/debug/libtrunk.a -o wrapper -lsodium -lresolv -framework Security -framework Foundation -Dc_char="char" && ./wrapper
