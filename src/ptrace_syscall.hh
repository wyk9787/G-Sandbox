#ifndef PTRACE_SYSCALL_HH
#define PTRACE_SYSCALL_HH

#include <sys/types.h>
#include <functional>
#include <memory>
#include <vector>

#include "ptrace_peek.hh"

class PtraceSyscall {
  using ull_t = unsigned long long;
  using handler_t = void (PtraceSyscall::*)(ull_t, ull_t, ull_t);

 public:
  PtraceSyscall(pid_t child_pid, bool read = false, bool read_write = false,
                bool fork = false, bool exec = false);

  void ProcessSyscall(int sys_num, ull_t rdi, ull_t rsi, ull_t rdx);

 private:
  void ReadHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void DefaultHandler(ull_t, ull_t, ull_t);

  bool read_;                             // able to read or not
  bool read_write_;                       // able to read and write or not
  bool fork_;                             // able to fork or not
  bool exec_;                             // able to exec or not
  std::vector<handler_t> handler_funcs_;  // handler functions
  std::unique_ptr<PtracePeek>
      ptrace_peek_;  // a helper to peek into tracee's memory
};

#endif  // PTRACE_SYSCALL_HH
