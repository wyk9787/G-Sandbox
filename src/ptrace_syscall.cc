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
  handler_funcs_[SYS_read] = &PtraceSyscall::ReadHandler;
}

void PtraceSyscall::ProcessSyscall(int sys_num, ull_t rdi, ull_t rsi,
                                   ull_t rdx) {
  (this->*handler_funcs_[sys_num])(rdi, rsi, rdx);
}

void PtraceSyscall::ReadHandler(ull_t rdi, ull_t rsi, ull_t rdx) {
  if (read_.empty() && read_write_.empty()) {
    std::cout << "The program calls read(" << rdi << ", " << rsi << ", " << rdx
              << ")" << std::endl;
    std::cout << "It is about to read "
              << ptrace_peek_.get(reinterpret_cast<void *>(rsi), rdx)
              << std::endl;
    REQUIRE(kill(child_pid_, SIGKILL) == 0) << "kill failed: "
                                            << strerror(errno);
    exit(1);
  } else {
    // TODO: add permission control
    return;
  }
}

