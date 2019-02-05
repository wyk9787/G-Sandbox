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
  PtraceSyscall(pid_t child_pid, std::string read = "", std::string read_write = "",
                bool fork = false, bool exec = false);

  void ProcessSyscall(int sys_num, ull_t rdi, ull_t rsi, ull_t rdx);

 private:
  void DefaultHandler(ull_t, ull_t, ull_t) {}

  void ReadHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void WiteHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void OpenHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void StatHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void FStatHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void LStatHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void SocketHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void ForkHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void CloneHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void VForkHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void ExecveHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void TruncateHandler(ull_t rdi, ull_t rsi, ull_t rdx);
  void ChdirHandler(ull_t rdi, ull_t rsi, ull_t rdx);

  pid_t child_pid_;                       // child process's pid
  std::string read_;                             // files able to read 
  std::string read_write_;                       // files able to read and write
  bool fork_;                             // able to fork or not
  bool exec_;                             // able to exec or not
  std::vector<handler_t> handler_funcs_;  // handler functions
  PtracePeek ptrace_peek_;  // a helper to peek into tracee's memory
};

#endif  // PTRACE_SYSCALL_HH
