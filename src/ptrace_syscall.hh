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
#define R10 3
#define R8 4

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

  void KillChild(std::string exit_message) const;

  void FileReadPermissionCheck(const std::string& file) const;
  void FileReadWritePermissionCheck(const std::string& file) const;

  void OpenHandler(const std::vector<ull_t>& args) const;
  void StatHandler(const std::vector<ull_t>& args) const;
  void LStatHandler(const std::vector<ull_t>& args) const;
  void SocketHandler(const std::vector<ull_t>& args) const;
  void CloneHandler(const std::vector<ull_t>& args) const;
  void ForkHandler(const std::vector<ull_t>& args) const;
  void VForkHandler(const std::vector<ull_t>& args) const;
  void ExecveHandler(const std::vector<ull_t>& args) const;
  void TruncateHandler(const std::vector<ull_t>& args) const;
  void GetcwdHandler(const std::vector<ull_t>& args) const;
  void ChdirHandler(const std::vector<ull_t>& args) const;
  void RenameHandler(const std::vector<ull_t>& args) const;
  void MkdirHandler(const std::vector<ull_t>& args) const;
  void RmdirHandler(const std::vector<ull_t>& args) const;
  void CreateHandler(const std::vector<ull_t>& args) const;
  void LinkHandler(const std::vector<ull_t>& args) const;
  void UnlinkHandler(const std::vector<ull_t>& args) const;
  void SymlinkHandler(const std::vector<ull_t>& args) const;
  void ReadlinkHandler(const std::vector<ull_t>& args) const;
  void ChmodHandler(const std::vector<ull_t>& args) const;
  void ChownHandler(const std::vector<ull_t>& args) const;
  void LChownHandler(const std::vector<ull_t>& args) const;

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
