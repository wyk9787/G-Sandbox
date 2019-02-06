#include "ptrace_syscall.hh"

#include <signal.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <iostream>

using std::string;

PtraceSyscall::PtraceSyscall(pid_t child_pid, string read, string read_write,
                             bool fork, bool exec)
    : child_pid_(child_pid),
      read_(read),
      read_write_(read_write),
      fork_(fork),
      exec_(exec),
      ptrace_peek_(child_pid) {
  handler_funcs_.insert(handler_funcs_.begin(), /*total_num_of_syscalls=*/314,
                        &PtraceSyscall::DefaultHandler);
  handler_funcs_[SYS_open] = &PtraceSyscall::OpenHandler;
}

void PtraceSyscall::ProcessSyscall(int sys_num,
                                   const std::vector<ull_t> &args) {
  (this->*handler_funcs_[sys_num])(args);
}

void PtraceSyscall::OpenHandler(const std::vector<ull_t> &args) {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  if (read_.empty() && read_write_.empty()) {
    std::cout << "The program calls open(" << rdi << ", " << rsi << ", " << rdx
              << ")" << std::endl;
    std::cout << "It is about to read "
              << ptrace_peek_[reinterpret_cast<void *>(rdi)] << std::endl;
    REQUIRE(kill(child_pid_, SIGKILL) == 0) << "kill failed: "
                                            << strerror(errno);
    exit(1);
  } else {
    // TODO: add permission control
    return;
  }
}

