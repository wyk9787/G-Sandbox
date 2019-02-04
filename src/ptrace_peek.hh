#ifndef PTRACE_PEEK_HH
#define PTRACE_PEEK_HH

#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include "log.h"

class PtracePeek {
 public:
  PtracePeek(pid_t child_pid) : child_pid_(child_pid){};

  long operator[](void *addr) {
    long ret = ptrace(PTRACE_PEEKDATA, child_pid_, addr, 0);
    REQUIRE(ret != -1) << "ptrace PTRACE_PEEKDATA failed: " << strerror(errno);
    return ret;
  }

 private:
  pid_t child_pid_;
};

#endif  // PTRACE_PEEK_HH
