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
                             bool socketable)
    : child_pid_(child_pid),
      read_file_detector_(read),
      read_write_file_detector_(read_write),
      socket_(socketable),
      ptrace_peek_(child_pid) {
  // Initilize handler_funcs_
  handler_funcs_.insert(handler_funcs_.begin(), /*total_num_of_syscalls=*/314,
                        &PtraceSyscall::DefaultHandler);
  handler_funcs_[SYS_open] = &PtraceSyscall::OpenHandler;
  handler_funcs_[SYS_stat] = &PtraceSyscall::StatHandler;
  handler_funcs_[SYS_lstat] = &PtraceSyscall::LStatHandler;
  handler_funcs_[SYS_socket] = &PtraceSyscall::SocketHandler;
  handler_funcs_[SYS_clone] = &PtraceSyscall::CloneHandler;
  handler_funcs_[SYS_fork] = &PtraceSyscall::ForkHandler;
  handler_funcs_[SYS_vfork] = &PtraceSyscall::VForkHandler;
  handler_funcs_[SYS_execve] = &PtraceSyscall::ExecveHandler;
  handler_funcs_[SYS_truncate] = &PtraceSyscall::TruncateHandler;
  handler_funcs_[SYS_getcwd] = &PtraceSyscall::GetcwdHandler;
  handler_funcs_[SYS_chdir] = &PtraceSyscall::ChdirHandler;
  handler_funcs_[SYS_rename] = &PtraceSyscall::RenameHandler;
  handler_funcs_[SYS_mkdir] = &PtraceSyscall::MkdirHandler;
  handler_funcs_[SYS_rmdir] = &PtraceSyscall::RmdirHandler;
  handler_funcs_[SYS_creat] = &PtraceSyscall::CreatHandler;
  handler_funcs_[SYS_link] = &PtraceSyscall::LinkHandler;
  handler_funcs_[SYS_unlink] = &PtraceSyscall::UnlinkHandler;
  handler_funcs_[SYS_symlink] = &PtraceSyscall::SymlinkHandler;
  handler_funcs_[SYS_readlink] = &PtraceSyscall::ReadlinkHandler;
  handler_funcs_[SYS_chmod] = &PtraceSyscall::ChmodHandler;
  handler_funcs_[SYS_chown] = &PtraceSyscall::ChownHandler;
  handler_funcs_[SYS_lchown] = &PtraceSyscall::LChownHandler;
  handler_funcs_[SYS_kill] = &PtraceSyscall::KillHandler;
  handler_funcs_[SYS_tkill] = &PtraceSyscall::TkillHandler;
  handler_funcs_[SYS_tgkill] = &PtraceSyscall::TgkillHandler;
  handler_funcs_[SYS_rt_sigqueueinfo] = &PtraceSyscall::RtSigqueueinfoHandler;
  handler_funcs_[SYS_rt_tgsigqueueinfo] =
      &PtraceSyscall::RtTgsigqueueinfoHandler;
  handler_funcs_[SYS_openat] = &PtraceSyscall::OpenatHandler;
}

void PtraceSyscall::ProcessSyscall(int sys_num,
                                   const std::vector<ull_t> &args) {
  INFO << " The program made syscall " << sys_num;
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
  } else {
    KillChild("The file is not granted read-write permission");
  }
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
  } else {
    FileReadPermissionCheck(file);
  }
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
  if (socket_) {
    INFO << "The program is granted socket permission.";
  } else {
    KillChild("The program is not allowed to perform socket operations");
  }
}

void PtraceSyscall::CloneHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  ull_t r10 = args[R10];
  ull_t r8 = args[R8];
  INFO << "The program calls clone(" << rdi << ", " << rsi << ", " << rdx
       << ", " << r10 << ", " << r8 << ")";
}

void PtraceSyscall::ForkHandler(const std::vector<ull_t> &args) const {
  INFO << "The program calls fork()";
}

void PtraceSyscall::VForkHandler(const std::vector<ull_t> &args) const {
  INFO << "The program calls vfork()";
}

void PtraceSyscall::ExecveHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = "";
  if (rdi != 0) {
    file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  }
  INFO << "The program calls execve(" << file << ", " << rsi << ", " << rdx
       << ")";
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
  FileReadPermissionCheck(file);
}

void PtraceSyscall::RenameHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  std::string original_name = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  std::string new_name = ptrace_peek_[reinterpret_cast<void *>(rsi)];
  INFO << "The program calls rename(" << original_name << ", " << new_name
       << ")";
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

void PtraceSyscall::CreatHandler(const std::vector<ull_t> &args) const {
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
  std::string path1 = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  std::string path2 = ptrace_peek_[reinterpret_cast<void *>(rsi)];
  INFO << "The program calls symlink(" << path1 << ", " << path2 << ")";
  // The symbolic link is linked from path2 to path1
  // Thus, we need write permission in path2 and read permission in path1
  FileReadWritePermissionCheck(path2);
  FileReadPermissionCheck(path1);
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
  FileReadWritePermissionCheck(file);
}

void PtraceSyscall::ChownHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls chown(" << file << ", " << rsi << ", " << rdx
       << ")";
  FileReadWritePermissionCheck(file);
}

void PtraceSyscall::LChownHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rdi)];
  INFO << "The program calls lchown(" << file << ", " << rsi << ", " << rdx
       << ")";
  FileReadWritePermissionCheck(file);
}

void PtraceSyscall::KillHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  INFO << "The program calls kill(" << rdi << ", " << rsi << ")";
  KillChild("The program is not allowed to send signals");
}

void PtraceSyscall::TkillHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  INFO << "The program calls tkill(" << rdi << ", " << rsi << ")";
  KillChild("The program is not allowed to send signals");
}

void PtraceSyscall::TgkillHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  INFO << "The program calls tgkill(" << rdi << ", " << rsi << ", " << rdx
       << ")";
  KillChild("The program is not allowed to send signals");
}

void PtraceSyscall::RtSigqueueinfoHandler(
    const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  INFO << "The program calls rt_sigqueueinfo(" << rdi << ", " << rsi << ", "
       << rdx << ")";
  KillChild("The program is not allowed to send signals");
}

void PtraceSyscall::RtTgsigqueueinfoHandler(
    const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  ull_t r10 = args[R10];
  INFO << "The program calls rt_tgsigqueueinfo(" << rdi << ", " << rsi << ", "
       << rdx << ", " << r10 << ")";
  KillChild("The program is not allowed to send signals");
}

void PtraceSyscall::OpenatHandler(const std::vector<ull_t> &args) const {
  ull_t rdi = args[RDI];
  ull_t rsi = args[RSI];
  ull_t rdx = args[RDX];
  std::string file = ptrace_peek_[reinterpret_cast<void *>(rsi)];
  INFO << "The program calls openat(" << rdi << ", " << file << ", " << rdx
       << ")";
  KillChild("The program is not allowed to call openat(). Use open() instead");
}
