#include "ptrace_syscall.hh"

#include <iostream>

PtraceSyscall::PtraceSyscall(pid_t child_pid, bool read, bool read_write,
                             bool fork, bool exec)
    : read_(read),
      read_write_(read_write),
      fork_(fork),
      exec_(exec),
      ptrace_peek_(std::make_unique<PtracePeek>(child_pid)) {
  handler_funcs_.insert(handler_funcs_.begin(), 300,
                        &PtraceSyscall::DefaultHandler);
  handler_funcs_.insert(handler_funcs_.begin(), &PtraceSyscall::ReadHandler);
}

void PtraceSyscall::ProcessSyscall(int sys_num, ull_t rdi, ull_t rsi,
                                   ull_t rdx) {
  (this->*handler_funcs_[sys_num])(rdi, rsi, rdx);
}

void PtraceSyscall::ReadHandler(ull_t rdi, ull_t rsi, ull_t rdx) {
  if (read_ || read_write_) {
    return;  // It is okay to read
  } else {
    std::cout << "The program calls read(" << rdi << ", " << rsi << ", " << rdx
              << ")" << std::endl;
    std::cout << "It is about to read "
              << ptrace_peek_[reinterpret_cast<void *>(rsi)]
  }
}

void PtraceSyscall::DefaultHandler(ull_t, ull_t, ull_t) {
  std::cout << "Entering default handler\n";
}

