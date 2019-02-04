#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"
#include "ptrace_syscall.hh"

// Trace a process with child_pid
void Trace(pid_t child_pid) {
  // Now repeatedly resume and trace the program
  bool running = true;
  int last_signal = 0;
  int status;
  while (running) {
    // Continue the process, delivering the last signal we received (if any)
    REQUIRE(ptrace(PTRACE_SYSCALL, child_pid, NULL, last_signal) != -1)
        << "ptrace PTRACE_SYSCALL failed: " << strerror(errno);

    // No signal to send yet
    last_signal = 0;

    // Wait for the child to stop again
    REQUIRE(waitpid(child_pid, &status, 0) == child_pid)
        << "waitpid failed: " << strerror(errno);

    if (WIFEXITED(status)) {
      printf("Child exited with status %d\n", WEXITSTATUS(status));
      running = false;
    } else if (WIFSIGNALED(status)) {
      printf("Child terminated with signal %d\n", WTERMSIG(status));
      running = false;
    } else if (WIFSTOPPED(status)) {
      // Get the signal delivered to the child
      last_signal = WSTOPSIG(status);

      // If the signal was a SIGTRAP, we stopped because of a system call
      if (last_signal == SIGTRAP) {
        // Read register state from the child process
        struct user_regs_struct regs;
        REQUIRE(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) != -1)
            << "ptrace PTRACE_GETREGS failed: " << strerror(errno);

        // Get the system call number
        size_t syscall_num = regs.orig_rax;

        // Print the systam call number and register values
        // The meanings of registers will depend on the system call.
        // Refer to the table at https://filippo.io/linux-syscall-table/
        printf("Program made system call %lu.\n", syscall_num);
        printf("  %%rdi: 0x%llx\n", regs.rdi);
        printf("  %%rsi: 0x%llx\n", regs.rsi);
        printf("  %%rdx: 0x%llx\n", regs.rdx);
        printf("  ...\n");

        last_signal = 0;
        PtraceSyscall ptrace_syscall(syscall_num);
        ptrace_syscall.ProcessSyscall();
      }
    }
  }
}

int main() {
  // Call fork to create a child process
  pid_t child_pid = fork();
  REQUIRE(child_pid != -1) << "fork failed: " << strerror(errno);

  // If this is the child, ask to be traced
  if (child_pid == 0) {
    REQUIRE(ptrace(PTRACE_TRACEME, 0, NULL, NULL) != -1)
        << "ptrace failed: " << strerror(errno);

    // Stop the process so the tracer can catch it
    raise(SIGSTOP);

    // TODO: Remove this after testing
    if (execlp("ls", "ls", NULL)) {
      perror("execlp failed");
      exit(2);
    }
  } else {
    // Wait for the child to stop
    int status;
    int result;
    do {
      result = waitpid(child_pid, &status, 0);
      REQUIRE(result == child_pid) << "waitpid failed: " << strerror(errno);
    } while (!WIFSTOPPED(status));

    // We are now attached to the child process
    printf("Attached!\n");

    Trace(child_pid);
  }

  return 0;
}
