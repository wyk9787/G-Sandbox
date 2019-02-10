#ifndef PTRACE_PEEK_HH
#define PTRACE_PEEK_HH

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include "log.h"

// This class provides a method to peek into trace's memory and read its data
class PtracePeek {
 public:
  PtracePeek(pid_t child_pid) : child_pid_(child_pid){};

  // Peek into tracee's program and read a string out of address _addr_
  std::string operator[](void* addr) const {
    size_t num_count = 0;
    char str[100];
    bool if_break = false;
    while (1) {
      char* cur_str = str + num_count * sizeof(long);
      long ret =
          ptrace(PTRACE_PEEKDATA, child_pid_,
                 reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) +
                                         num_count * sizeof(long)),
                 0);
      REQUIRE(ret != -1) << "ptrace PTRACE_PEEKDATA failed: "
                         << strerror(errno);

      memcpy(cur_str, &ret, sizeof(long));
      for (size_t i = 0; i < sizeof(long); ++i) {
        if (cur_str[i] == '\0') {
          if_break = true;
          break;
        }
      }
      if (if_break) break;
      num_count++;
    }

    return std::string(str);
  }

 private:
  pid_t child_pid_;  // tracee's pid
};

#endif  // PTRACE_PEEK_HH
