#! /bin/sh

cd out/build

g++  -Wall -Wextra -ggdb3   ../../headers/crypto.cpp -o crypto.o -c -I ../../libraries/ssl/include -I libraries

g++  -Wall -Wextra -ggdb3  -c ../../src/trial.cpp -o trial.o -I ../../

gcc  -g  -c ../../libraries/sqlite/build/sqlite3.c -o sqlite3.o -I ../../libraries/sqlite/build/


g++  -Wall -Wextra -ggdb3    -o trial trial.o crypto.o sqlite3.o -L libcrypto.a -lssl -lcrypto -lsqlite3 -lpthread -ldl -g -static-libstdc++ -static-libgcc -static 
