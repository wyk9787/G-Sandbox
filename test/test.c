#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
  // Run a few system calls that are allowed
  void* test_mmap = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (test_mmap == MAP_FAILED) {
    perror("mmap");
    exit(2);
  }
  close(0);
  mprotect(test_mmap, 4096, PROT_NONE);

  // Run a few system calls that are permission controled
  int read_fd = open("/usr/local/include/test.h", O_RDONLY, 0);
  int write_fd = open("/usr/local/include/test.h", O_WRONLY, 0);

  // Fork
  pid_t child_pid = fork();
  if (child_pid == -1) {
    perror("fork");
    exit(2);
  } else if (child_pid != 0) {
    // Parent process
    printf("Inside parent\n");
    wait(NULL);

    struct hostent* server = gethostbyname("www.grinnell.edu");
    if (server == NULL) {
      fprintf(stderr, "Unable to find host %s\n", "www.grinnell.edu");
      exit(1);
    }

    // Test socket
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
      perror("socket failed");
      exit(2);
    }
  } else {
    // Child process
    printf("Inside child\n");

    // Run exec
    if (execlp("ls", "ls", NULL)) {
      perror("execlp failed");
      exit(2);
    }
  }

  printf("Finished the program\n");
}
