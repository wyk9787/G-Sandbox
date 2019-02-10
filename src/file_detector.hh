#ifndef FILE_DETECTOR_HH
#define FILE_DETECTOR_HH

#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>
#include <string>

#include "log.h"

// This class detects if a file is allowed by the sandbox
class FileDetector {
 public:
  FileDetector(std::string whitelist) : whitelist_(whitelist) {
    char* tmp;
    REQUIRE((tmp = realpath(".", NULL)) != NULL) << "realpath() failed: "
                                                 << strerror(errno);
    cur_path_ = std::string(tmp) + "/";
    free(tmp);
  }

  // Decide if the file _file_ is a subdirectory of the whitelist
  // _file_ can be a relative or absolute path
  bool IsAllowed(std::string file) const {
    if (whitelist_.empty()) {
      return false;
    }

    // If file is a relative path, make it absolute
    if (file[0] == '.' || file[0] != '/' || file[0] == '.') {
      file = cur_path_ + file;
    }

    // If file is a subdirectory of whitelist_, then whitelist_ must be a
    // substring of file
    if (file.find(whitelist_) != std::string::npos) {
      return true;
    } else {
      return false;
    }
  }

 private:
  std::string cur_path_;  // current path
  std::string
      whitelist_;  // directory and its subdirectory permitted to read or write
};

#endif  // FILE_DETECTOR_HH
