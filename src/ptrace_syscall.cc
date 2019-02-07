#include "ptrace_syscall.hh"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>

using std::string;

PtraceSyscall::PtraceSyscall(pid_t child_pid, string read, string read_write,
                             bool fork, bool exec)
    : child_pid_(child_pid),
      read_file_detector_(read),
      read_write_file_detector_(read_write),
      fork_(fork),
      exec_(exec),
      ptrace_peek_(child_pid) {
  handler_funcs_.insert(handler_funcs_.begin(), /*total_num_of_syscalls=*/314,
                        &PtraceSyscall::DefaultHandler);
  handler_funcs_[SYS_open] = &PtraceSyscall::OpenHandler;
  handler_funcs_[SYS_stat] = &PtraceSyscall::StatHandler;
}

void PtraceSyscall::ProcessSyscall(int sys_num,
                                   const std::vector<ull_t> &args) {
  (this->*handler_funcs_[sys_num])(args);
}

void PtraceSyscall::OpenHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls open(\"" << file << "\", " << rsi << ", " << rdx
       << ")";

  bool allow_read = read_file_detector_.IsAllowed(file);
  bool allow_read_write = read_write_file_detector_.IsAllowed(file);

  if (rsi & O_WRONLY) {
    if (allow_read_write) {
      INFO << "The file is granted write permission";
    }
    REQUIRE(kill(child_pid_, SIGKILL) == 0) << "kill failed: "
                                            << strerror(errno);
    FATAL << "The file is not granted write permission";
  }

  if (rsi & O_RDWR) {
    if (allow_read_write) {
      INFO << "The file is granted read-write permission";
    }
    REQUIRE(kill(child_pid_, SIGKILL) == 0) << "kill failed: "
                                            << strerror(errno);
    FATAL << "The file is not granted read-write permission";
  }

  if (allow_read || allow_read_write) {
    INFO << "The file is granted read permission";
    return;
  }

  REQUIRE(kill(child_pid_, SIGKILL) == 0) << "kill failed: " << strerror(errno);
  FATAL << "The file is not granted read permission";
}

void PtraceSyscall::StatHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls stat(\"" << file << "\", " << rsi << ")";
  if (read_file_detector_.IsAllowed(file) ||
      read_write_file_detector_.IsAllowed(file)) {
    INFO << "The file is granted read permission";

  } else {
    REQUIRE(kill(child_pid_, SIGKILL) == 0) << "kill failed: "
                                            << strerror(errno);
    FATAL << "The file is not granted read permission";
  }
}

