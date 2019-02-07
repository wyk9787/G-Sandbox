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
  handler_funcs_[SYS_newstat] = &PtraceSyscall::StatHandler;
  handler_funcs_[SYS_newlstat] = &PtraceSyscall::LStatHandler;
  handler_funcs_[SYS_socket] = &PtraceSyscall::SocketHandler;
}

void PtraceSyscall::ProcessSyscall(int sys_num,
                                   const std::vector<ull_t> &args) {
  (this->*handler_funcs_[sys_num])(args);
}

void PtraceSyscall::KillChild(std::string exit_message) const {
  REQUIRE(kill(child_pid_, SIGKILL) == 0) << "kill failed: " << strerror(errno);
  FATAL << exit_message;
}

void PtraceSyscall::FileReadPermissionCheck(const string &file) const {
  if (read_file_detector_.IsAllowed(file) ||
      read_write_file_detector_.IsAllowed(file)) {
    INFO << "The file is granted read permission";

  } else {
    KillChild("The file is not granted read permission");
  }
}

void PtraceSyscall::FileReadWritePermissionCheck(const string &file) const {
  if (read_write_file_detector_.IsAllowed(file)) {
    INFO << "The file is granted read-write permission";
  }
  KillChild("The file is not granted read-write permission");
}

void PtraceSyscall::OpenHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls open(\"" << file << "\", " << rsi << ", " << rdx
       << ")";

  if (rsi & (O_WRONLY | O_RDWR)) {
    FileReadWritePermissionCheck(file);
  }

  FileReadPermissionCheck(file);
}

void PtraceSyscall::StatHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls stat(\"" << file << "\", " << rsi << ")";
  FileReadPermissionCheck(file);
}

void PtraceSyscall::LStatHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls lstat(\"" << file << "\", " << rsi << ")";
  FileReadPermissionCheck(file);
}

void PtraceSyscall::SocketHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  INFO << "The program calls socket(" << rdi << ", " << rsi << ", " << rdx
       << ")";
}

void PtraceSyscall::CloneHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  ull_t r10 = args[R10];
  ull_t r8 = args[R8];
  // TODO: Peek at other parameters?
  INFO << "The program calls clone(" << rdi << ", " << rsi << ", " << rdx
       << ", " << r10 << ", " << r8 << ")";
  if (fork_) return;
  KillChild("The program is not allowed to fork or clone");
}

void PtraceSyscall::ForkHandler(const std::vector<ull_t> &args) const {
  INFO << "The program calls fork()";
  if (fork_) return;
  KillChild("The program is not allowed to fork or clone");
}

void PtraceSyscall::VForkHandler(const std::vector<ull_t> &args) const {
  INFO << "The program calls vfork()";
  if (fork_) return;
  KillChild("The program is not allowed to fork or clone");
}

void PtraceSyscall::ExecveHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  // TODO: Peek at other parameters?
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls execve(" << file << ", " << rsi << ", " << rdx
       << ")";
  if (exec_) return;
  KillChild("The program is not allowed to call exec");
}

void PtraceSyscall::TruncateHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls truncate(" << file << ", " << rsi << ")";
  FileReadWritePermissionCheck(file);
}

void PtraceSyscall::GetcwdHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  INFO << "The program calls getcwd(" << rdi << ", " << rsi << ")";
  // Reading the current directory so file = "."
  FileReadPermissionCheck(".");
}

void PtraceSyscall::ChdirHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls chdir(" << file << ")";
  // TODO: What about having write permission
  KillChild("The program is not allowed to change directory");
}

void PtraceSyscall::RenameHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string original_name = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  std::string new_name = ptrace_peek_[reinterpret_cast<void *>(rsi)];
  INFO << "The program calls rename(" << original_name << ", " << new_name
       << ")";
  // TODO: What about having write permission
  FileReadWritePermissionCheck(original_name);
  FileReadWritePermissionCheck(new_name);
}

void PtraceSyscall::MkdirHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string directory_name = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls mkdir(" << directory_name << ", " << rsi << ")";
  FileReadWritePermissionCheck(directory_name);
}

void PtraceSyscall::RmdirHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  std::string directory_name = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls rmdir(" << directory_name << ")";
  FileReadWritePermissionCheck(directory_name);
}

void PtraceSyscall::CreateHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls create(" << file << ", " << rsi << ")";
  FileReadWritePermissionCheck(file);
}

void PtraceSyscall::LinkHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string original_path = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  std::string new_path = ptrace_peek_[reinterpret_cast<void *>(rsi)];
  INFO << "The program calls link(" << original_path << ", " << new_path << ")";
  FileReadWritePermissionCheck(original_path);
  FileReadWritePermissionCheck(new_path);
}

void PtraceSyscall::UnlinkHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  std::string original_path = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls unlink(" << original_path << ")";
  FileReadWritePermissionCheck(original_path);
}

void PtraceSyscall::SymlinkHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string original_path = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  std::string new_path = ptrace_peek_[reinterpret_cast<void *>(rsi)];
  INFO << "The program calls symlink(" << original_path << ", " << new_path
       << ")";
  KillChild("The program is not allowed to create symbolic link");
}

void PtraceSyscall::ReadlinkHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls readlink(" << file << ", " << rsi << ", " << rdx
       << ")";
  FileReadPermissionCheck(file);
}

void PtraceSyscall::ChmodHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls chmod(" << file << ", " << rsi << ")";
  KillChild("The program is not allowed to change permission of the file");
}

void PtraceSyscall::ChownHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls chown(" << file << ", " << rsi << ", " << rdx
       << ")";
  KillChild(
      "The program is not allowed to change owner or the group of the file");
}

void PtraceSyscall::LChownHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls lchown(" << file << ", " << rsi << ", " << rdx
       << ")";
  KillChild(
      "The program is not allowed to change owner or the group of the file");
}
