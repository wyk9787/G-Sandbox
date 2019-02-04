#include <libconfig.h>

int main() {
  Config cfg;
  cfg.readFile("example.cfg");
  std::string name = cfg.lookup("name");
  std::cout << "Store name: " << name << std::endl << std::endl;
}

