#include "ptrace_syscall.hh"

#include <iostream>

PtraceSyscall::PtraceSyscall(int sys_num, ull_t rdi, ull_t rsi, ull_t rdx,
                             bool read, bool read_write, bool fork, bool exec)
    : sys_num_(sys_num),
      rdi_(rdi),
      rsi_(rsi),
      rdx_(rdx),
      read_(read),
      read_write_(read_write),
      fork_(fork),
      exec_(exec) {
  handler_funcs_.insert(handler_funcs_.begin(), 300,
                        &PtraceSyscall::DefaultHandler);
  handler_funcs_.insert(handler_funcs_.begin(), &PtraceSyscall::ReadHandler);
}

void PtraceSyscall::ProcessSyscall() { (this->*handler_funcs_[sys_num_])(); }

void PtraceSyscall::ReadHandler() {
  std::cout << "Entering read handler\n";
  std::cout << "read=" << read_ << ", read_write=" << read_write_ << std::endl;
}

void PtraceSyscall::DefaultHandler() {
  std::cout << "Entering default handler\n";
}

