#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libconfig.h++>

#include "file_detector.hh"
#include "log.h"
#include "ptrace_syscall.hh"

#define PTRACE_EXEC_STATUS (SIGTRAP | (PTRACE_EVENT_EXEC << 8))
#define PTRACE_CLONE_STATUS (SIGTRAP | (PTRACE_EVENT_CLONE << 8))
#define PTRACE_FORK_STATUS (SIGTRAP | (PTRACE_EVENT_FORK << 8))
#define PTRACE_VFORK_STATUS (SIGTRAP | (PTRACE_EVENT_VFORK << 8))

using libconfig::Config;
using libconfig::FileIOException;
using libconfig::ParseException;

static std::string read_file = "";
static std::string read_write_file = "";
static bool forkable = false;
static bool execable = false;
static bool socketable = false;

// Parse restrictions flags from configuration file
void ParseConfig(std::string config_file) {
  Config cfg;

  // Read the file. If there is an error, report it and exit.
  try {
    cfg.readFile(config_file.c_str());
  } catch (const FileIOException &fioex) {
    FATAL << "I/O error while reading file.";
  } catch (const ParseException &pex) {
    FATAL << "Parse error at " << pex.getFile() << ":" << pex.getLine() << " - "
          << pex.getError();
  }

  // Parse variables
  // If variable name cannot be found, passed in variables witll not be changed
  cfg.lookupValue("read", read_file);
  cfg.lookupValue("read_write", read_write_file);
  cfg.lookupValue("fork", forkable);
  cfg.lookupValue("exec", execable);
  cfg.lookupValue("socket", socketable);
}

// Trace a process with child_pid
void Trace(pid_t child_pid, bool root) {
  // Now repeatedly resume and trace the program
  bool running = true;
  int last_signal = 0;
  int status;
  size_t total_times = 0;
  PtraceSyscall ptrace_syscall(child_pid, read_file, read_write_file,
                               socketable);
  FileDetector read_file_detector(read_file);
  FileDetector read_write_file_detector(read_write_file);

  // Set options for ptrace to stop at exec(), clone(), fork(), and vfork()
  if (root) {
    REQUIRE(ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
                   PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK |
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK) != -1)
        << "ptrace PTRACE_SETOPTIONS failed: " << strerror(errno);
  }

  bool done_first_exec = false;
  while (running) {
    // Continue the process, delivering the last signal we received (if any)
    REQUIRE(ptrace(PTRACE_SYSCALL, child_pid, NULL, last_signal) != -1)
        << "ptrace PTRACE_SYSCALL failed: " << strerror(errno);

    // No signal to send yet
    last_signal = 0;

    // Wait for the child to stop again
    REQUIRE(waitpid(child_pid, &status, 0) == child_pid) << "waitpid failed: "
                                                         << strerror(errno);

    if (WIFEXITED(status)) {
      INFO << "Child exited with status " << WEXITSTATUS(status);
      running = false;
    } else if (WIFSIGNALED(status)) {
      INFO << "Child terminated with signal" << WTERMSIG(status);
      running = false;
    } else if (status >> 8 == PTRACE_EXEC_STATUS) {
      // The program just runs execv

      // If the tracee hasn't run the first exec that execs the actual program
      // yet
      if (!done_first_exec) {
        done_first_exec = true;
        last_signal = 0;
        continue;
      }

      if (execable) {
        last_signal = 0;
      } else {
        ptrace_syscall.KillChild("The program is not allowed to exec");
      }
    } else if (status >> 8 == PTRACE_FORK_STATUS ||
               status >> 8 == PTRACE_CLONE_STATUS ||
               status >> 8 == PTRACE_VFORK_STATUS) {
      // The program just called clone

      if (forkable) {
        pid_t new_child_pid;
        REQUIRE(ptrace(PTRACE_GETEVENTMSG, child_pid, NULL,
                       reinterpret_cast<void *>(&new_child_pid)) != -1)
            << "ptrace PTRACE_GETEVENTMSG failed: " << strerror(errno);
        INFO << new_child_pid;
        sleep(1);
        REQUIRE(ptrace(PTRACE_SYSCALL, new_child_pid, NULL, 0) != -1)
            << "ptrace PTRACE_SYSCALL failed: " << strerror(errno);
        /* pid_t new_tracer_pid = fork(); */
        /* REQUIRE(new_tracer_pid != -1) << "fork failed"; */
        /* if (new_tracer_pid == 0) { */
        /*   Trace(new_child_pid, false); */
        /*   exit(0); */
        /* } else { */
        /*   last_signal = 0; */
        /* } */
      } else {
        ptrace_syscall.KillChild("The program is not allowed to fork");
      }
    } else if (WIFSTOPPED(status)) {
      // Get the signal delivered to the child
      last_signal = WSTOPSIG(status);

      // If the signal was a SIGTRAP, we stopped because of a system call
      if (last_signal == SIGTRAP) {
        // We do not want to send SIGTRAP again to the tracee
        last_signal = 0;

        // Keep track of we are before the syscall or after the syscall
        // In order to avoid over flow, we mod 2
        total_times = (total_times + 1) % 2;

        // This is the second time we see this system call (after the execution)
        // We ignore it
        if (total_times % 2 == 0) {
          continue;
        }
        // Read register state from the child process
        struct user_regs_struct regs;
        REQUIRE(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) != -1)
            << "ptrace PTRACE_GETREGS failed: " << strerror(errno);

        // Get the system call number
        size_t syscall_num = regs.orig_rax;

        std::vector<unsigned long long> args = {regs.rdi, regs.rsi, regs.rdx,
                                                regs.r10, regs.r8,  regs.r9};

        ptrace_syscall.ProcessSyscall(syscall_num, args);
      }
    }
  }
}

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cout << "Usage: ./sandbox (config_file) -- program arg1 arg2 ..."
              << std::endl;
    exit(1);
  }

  char **program;
  if (std::string(argv[1]) == "--") {
    // Without config file
    program = &argv[2];
  } else {
    // With config file
    std::string config_file(argv[1]);
    ParseConfig(config_file);
    program = &argv[3];
  }

  // Call fork to create a child process
  pid_t child_pid = fork();
  REQUIRE(child_pid != -1) << "fork failed: " << strerror(errno);

  // If this is the child, ask to be traced
  if (child_pid == 0) {
    REQUIRE(ptrace(PTRACE_TRACEME, 0, NULL, NULL) != -1) << "ptrace failed: "
                                                         << strerror(errno);

    // Stop the process so the tracer can catch it
    raise(SIGSTOP);

    REQUIRE(execvp(program[0], program)) << "execvp failed: "
                                         << strerror(errno);
  } else {
    // Wait for the child to stop
    int status;
    int result;
    do {
      result = waitpid(child_pid, &status, 0);
      REQUIRE(result == child_pid) << "waitpid failed: " << strerror(errno);
    } while (!WIFSTOPPED(status));

    Trace(child_pid, true);
  }

  return 0;
}

