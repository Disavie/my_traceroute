#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#define DEFAULT_PORT "80"

int main(int argc, char ** argv){
  
  fprintf(stdout, "checking ip of: %s\n", argv[1]);
  struct addrinfo *inf = NULL;
  int rc = 0;
  struct addrinfo hints = {};
  hints.ai_flags = AI_ADDRCONFIG |AI_CANONNAME;

  rc = getaddrinfo( argv[1], DEFAULT_PORT, &hints, &inf);
  if(rc != 0){ //-2 -> name/service is unknown
    fprintf(stderr, "rc: %d\n", rc);
    perror("getaddrinfo");
    exit(EXIT_FAILURE);
  }


  printf("is AF_INET?: %d\n", inf->ai_family == AF_INET);
  printf("is SOCK_STREAM?: %d\n", inf->ai_socktype == SOCK_STREAM);
  printf("data: %s\n", inf->ai_addr->sa_data);
  printf("cannonname: %s\n", inf->ai_canonname);

  struct sockaddr_in addr = {
     inf->ai_family, //sa_family_t
     0,
  };
  //socket
  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if(sock_fd == -1){
    perror("socket");
    exit(EXIT_FAILURE);
  }
  //connect
  rc = connect(sock_fd, inf->ai_addr, inf->ai_addrlen);
  if(rc == -1){
    perror("connect");
    exit(EXIT_FAILURE);
  }
  fprintf(stdout,"connected\n");
  freeaddrinfo(inf);

  //send
  uint64_t msg = 0;
  const uint64_t top = 0b00001000000000000000000000000000;
  msg = top << 32;
  pid_t pid = getpid();
  msg = htons(getpid()) << 16;
  msg = 
  rc = send(sock_fd, (void *)&msg, 8, 0);
  if (rc == -1){
    perror("send");
    exit(EXIT_FAILURE);
  }
  fprintf(stdout, "sent\n");
  
  //recv
  char buf[512];
  recv(sock_fd, buf, 512, 0);
  if (rc == -1){
    perror("recv");
    exit(EXIT_FAILURE);
  }
  fprintf(stdout, "%s\n", buf);
  return EXIT_SUCCESS;
}
