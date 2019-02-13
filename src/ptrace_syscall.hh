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

// This class processes the system calls we intercepted and based on the given
// permission, decide to either kill the tracee program or let it continue
class PtraceSyscall {
  using ull_t = unsigned long long;
  using handler_t =
      void (PtraceSyscall::*)(const std::vector<ull_t>& args) const;

 public:
  PtraceSyscall(pid_t child_pid, std::string read, std::string read_write,
                bool socketable);

  // Process the _sys_num_ system call with argument _args_
  void ProcessSyscall(int sys_num, const std::vector<ull_t>& args);

  // Kills the tracee program with error message _exit_message_
  void KillChild(std::string exit_message) const;

 private:
  // A placeholder handler function for system calls we do not intercept
  void DefaultHandler(const std::vector<ull_t>& args) const {}

  // Checks if the sandbox allows the file _file_ to be read
  // If not, kill the tracee program and reports the error
  void FileReadPermissionCheck(const std::string& file) const;

  // Checks if the sandbox allows the file _file_ to be read and write
  // If not, kill the tracee program and reports the error
  void FileReadWritePermissionCheck(const std::string& file) const;

  // Handlers for intercepted system calls
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
  void CreatHandler(const std::vector<ull_t>& args) const;
  void LinkHandler(const std::vector<ull_t>& args) const;
  void UnlinkHandler(const std::vector<ull_t>& args) const;
  void SymlinkHandler(const std::vector<ull_t>& args) const;
  void ReadlinkHandler(const std::vector<ull_t>& args) const;
  void ChmodHandler(const std::vector<ull_t>& args) const;
  void ChownHandler(const std::vector<ull_t>& args) const;
  void LChownHandler(const std::vector<ull_t>& args) const;
  void KillHandler(const std::vector<ull_t>& args) const;
  void TkillHandler(const std::vector<ull_t>& args) const;
  void TgkillHandler(const std::vector<ull_t>& args) const;
  void RtSigqueueinfoHandler(const std::vector<ull_t>& args) const;
  void RtTgsigqueueinfoHandler(const std::vector<ull_t>& args) const;
  void OpenatHandler(const std::vector<ull_t>& args) const;

  pid_t child_pid_;  // child process's pid
  FileDetector
      read_file_detector_;  // a file detector to decide read permission
  FileDetector read_write_file_detector_;  // a file detector to decide read and
                                           // write permission
  bool socket_;                            // able to do socket operation or not
  std::vector<handler_t> handler_funcs_;   // handler functions
  PtracePeek ptrace_peek_;  // a helper to peek into tracee's memory
};

#endif  // PTRACE_SYSCALL_HH
