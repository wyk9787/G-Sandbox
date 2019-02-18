#ifndef FILE_DETECTOR_HH
#define FILE_DETECTOR_HH

#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>
#include <sstream>
#include <string>
#include <unordered_set>

#include "log.h"

// This class detects if a file is allowed by the sandbox
class FileDetector {
 public:
  FileDetector(std::string whitelist) {
    char* tmp;
    REQUIRE((tmp = realpath(".", NULL)) != NULL) << "realpath() failed: "
                                                 << strerror(errno);
    cur_path_ = std::string(tmp) + "/";
    free(tmp);

    if (whitelist.empty()) return;

    std::stringstream ss(whitelist);
    while (ss.good()) {
      std::string substr;
      getline(ss, substr, ',');
      whitelists_.insert(substr);
    }
  }

  // Decide if the file _file_ is a subdirectory of the whitelist
  // _file_ can be a relative or absolute path
  bool IsAllowed(std::string file) const {
    if (whitelists_.empty()) {
      return false;
    }

    // If file is a relative path, make it absolute
    if (file[0] == '.' || file[0] != '/' || file[0] == '.') {
      file = cur_path_ + file;
    }

    // If file is a subdirectory of whitelist_, then whitelist_ must be a
    // substring of file
    for (const auto str : whitelists_) {
      INFO << str;
      if (file.find(str) != std::string::npos) {
        return true;
      }
    }
    return false;
  }

 private:
  std::string cur_path_;  // current path
  std::unordered_set<std::string>
      whitelists_;  // directory and its subdirectory permitted to read or write
};

#endif  // FILE_DETECTOR_HH
