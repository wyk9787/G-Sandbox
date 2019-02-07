#ifndef PTRACE_SYSCALL_HH
#define PTRACE_SYSCALL_HH

#include <sys/types.h>
#include <functional>
#include <memory>
#include <vector>

#include "file_detector.hh"
#include "ptrace_peek.hh"

#define RDI 0
#define RSI 1
#define RDX 2

class PtraceSyscall {
  using ull_t = unsigned long long;
  using handler_t =
      void (PtraceSyscall::*)(const std::vector<ull_t>& args) const;

 public:
  PtraceSyscall(pid_t child_pid, std::string read = "",
                std::string read_write = "", bool fork = false,
                bool exec = false);

  void ProcessSyscall(int sys_num, const std::vector<ull_t>& args);

 private:
  void DefaultHandler(const std::vector<ull_t>& args) const {}

  void OpenHandler(const std::vector<ull_t>& args) const;
  void StatHandler(const std::vector<ull_t>& args) const;
  void LStatHandler(std::vector<ull_t> args);
  /* void SocketHandler(std::vector<ull_t> args); */
  /* void ForkHandler(std::vector<ull_t> args); */
  /* void CloneHandler(std::vector<ull_t> args); */
  /* void VForkHandler(std::vector<ull_t> args); */
  /* void ExecveHandler(std::vector<ull_t> args); */
  /* void TruncateHandler(std::vector<ull_t> args); */
  /* void ChdirHandler(std::vector<ull_t> args); */

  pid_t child_pid_;  // child process's pid
  FileDetector
      read_file_detector_;  // a file detector to decide read permission
  FileDetector read_write_file_detector_;  // a file detector to decide read and
                                           // write permission
  bool fork_;                              // able to fork or not
  bool exec_;                              // able to exec or not
  std::vector<handler_t> handler_funcs_;   // handler functions
  PtracePeek ptrace_peek_;  // a helper to peek into tracee's memory
};

#endif  // PTRACE_SYSCALL_HH
