# G-Sandbox

This is a C++ sandbox tool that restricts certain system calls based on 
given priviledges. It will not only sandbox the program it runs but also any of 
its child processes.

## Required library

* [libconfig](https://github.com/hyperrealm/libconfig): C/C++ library for 
processing configuration files 

   ```cpp
   git clone https://github.com/hyperrealm/libconfig
   cd libconfig
   ./configure
   make         # may require sudo
   make install # may require sudo
   ```

* pkg-config: tool to find right library path for libconfig
   
   `sudo apt-get install pkg-config`

## Example Usage 

```
export LD_LIBRARY_PATH=/usr/local/lib
make

# You can also add NDEBUG macro to suppress logging to the console
make MACRO=NDEBUG

# Run ls with no priviledge
./sandbox -- ls

# Run ls with all priviledges besides sending signals to other process
./sandbox test/test4.cfg -- ls
```

## Restrictions 

* Changing the current directory

* Creating or removing directories

* Reading files anywhere on the system

* Writing files anywhere on the system

* Removing files anywhere on the system

* Sending signals to other processes on the system

* Performing socket operations

* Creating new processes with `fork`

* Executing new files with `exec`

## Grant priviledges through configuration file

* `read`: Grant the sandboxed program read-only access in a specific directory
and its subdirectories

   Programs may want to read shared library such as libc so we allow them to 
read certain directories and its subdirectories.

* `read-write`: Grant the sandboxed program read-write access (and the ability
to remove files, create directories, etc.) in a specific directory and its
subdirectories

   Programs may want to write to some temporary locations to record metadata or
other necessary information.
  
* `fork`: Allow the program to call `fork`

   Programs can be a multi-process program.

* `exec`: Allow the program to call `exec`

   Programs may want to execute other program to achieve some of its
functionality. 

* `socket`: Allow the program to call `socket`

  Programs may want to do some network operations. Although it can be
dangerous, the program can be more useful.

## Testing Instructions

### Overview

In this testing section, we demonstrate that G-Sandbox is able to trace every
system call and intercept the restricted ones. It can also lift some
restrictions by passing a priviledge config file to the program as an argument.
It able to sandbox all of user program's child processes as well.

All tests are testing on the program `test/test.c`, which does following steps:

1. It calls a few system calls that are not directly requiring priviledges
(however, linking various shared library such as glibc requires ceratin read
priviledges). 

2. It runs a few system calls that explicitly require priviledges
to run (e.g. `open`) 

3. It calls `fork` to create a child process.

4. The child process calls `exec` to run `ls` command, which invokes many
   system calls.

5. The parent process wait until child process to finish, then calls `socket`

### Build

```
export LD_LIBRARY_PATH=/usr/local/lib
make clean all  # (re)build G-Sandbox

cd test 
make clean all  # (re)build test program
cd ..   

```

### Testing

* `./sandbox -- test/test`

   The program is not given any priviledge. Thus, the program stopped at the
first system call(e.g. `open`).

* `./sandbox test/test1.cfg -- test/test`

   The program is given priviledge to read and write any file. The program is
stopped at `fork` because it does not have any fork priviledge.

* `./sandbox test/test2.cfg -- test/test`

   The program is given priviledge to read and write any file, and also create
child process. The program is stopped at `execve` because it does not have any 
exec priviledge.

* `./sandbox test/test3.cfg -- test/test`

   The program is given priviledge to read and write any file, and also create
child process and exec. The program is stopped at `socket` because it does not have any 
internet priviledge.

* `./sandbox test/test4.cfg -- test/test`

   The program has full priviledge so the program successfully finishes.

* `./sandbox test/test5.cfg -- test/test`

   The program has full priviledge besides `read` is set to a specific
directory. Since `read-write` is set to root directory, all files should be
able to be read.

* `./sandbox test/test6.cfg -- test/test`

  The program has priviledge to `fork`, `exec` and `socket` and read any file
on the system. However, it only has privilegde to write in `/lib/`. Thus, the
program is stopped at the second `open` operation which writes to a file that
is not in `/lib/` or its subdirectories. We also see that the previous `open`
call to read any shared libraries under `/lib/` and its subdirectories are
allowed.

## Reference & Acknowledgement

* [log.h](src/log.h) is borrowed from [Coz](https://github.com/plasma-umass/coz)

* [`ptrace` example code and lab
instructions](https://www.cs.grinnell.edu/~curtsinger/teaching/2019S/CSC395/labs/sandboxing/)

* Charlie Curtsinger
