#ifndef FILE_DETECTOR_HH
#define FILE_DETECTOR_HH

#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>
#include <string>

#include "log.h"

class FileDetector {
 public:
  FileDetector(std::string whitelist) : whitelist_(whitelist) {
    char *tmp_cur_path;
    REQUIRE((tmp_cur_path = get_current_dir_name()) != NULL)
        << "get_current_dir_name failed: " << strerror(errno);
    cur_path_ = std::string(tmp_cur_path) + "/";
    free(tmp_cur_path);
  }

  bool IsAllowed(std::string file) const {
    // If there is no allowed directory, then always false
    if (whitelist_.empty()) return false;

    // If file is a relative path, make it absolute
    if (file[0] == '.' || file[0] != '/') {
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
  std::string cur_path_;
  std::string whitelist_;
};

#endif  // FILE_DETECTOR_HH
