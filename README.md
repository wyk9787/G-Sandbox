# G-Sandbox

This is a toy C++ sandbox tool that restricts certain system calls based on given permission. It will not only sandbox the program it runs but also any of its child processes.

## Required library

* [libconfig](https://github.com/hyperrealm/libconfig): C/C++ library for processing configuration files 

   ```cpp
   git clone https://github.com/hyperrealm/libconfig
   cd libconfig
   ./configure
   make         # may require sudo
   make install # may require sudo
   ```

* pkg-config: tool to find right library path for libconfig
   
   `sudo apt-get install pkg-config`

## Installation 

```
export LD_LIBRARY_PATH=/usr/local/lib
make
```

## Reference & Acknowledgement

[log.h](src/log.h) is borrowed from [Coz](https://github.com/plasma-umass/coz)

