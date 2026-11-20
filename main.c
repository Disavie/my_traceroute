#include <bits/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

struct ip_header_t {
  uint8_t v_ihl;
  uint8_t dscp_ecn;
  uint16_t len;

  uint16_t id;
  uint16_t flags_fragoff;

  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;

  uint32_t src_addr;
  uint32_t dest_addr;
};
struct icmp_msg_t {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;

  uint16_t id;
  uint16_t seqno;
};


int main(int argc, char ** argv){
  
  fprintf(stdout, "checking ip of: %s\n", argv[1]);
  struct addrinfo *inf = NULL;
  int rc = 0;
  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_ADDRCONFIG |AI_CANONNAME;

  rc = getaddrinfo( argv[1], NULL, &hints, &inf);
  if(rc != 0){ //-2 -> name/service is unknown
    fprintf(stderr, "rc: %d\n", rc);
    perror("getaddrinfo");
    exit(EXIT_FAILURE);
  }


  printf("is AF_INET?: %d\n", inf->ai_family == AF_INET);
  printf("socktype?: %d\n", inf->ai_socktype);
  printf("data: %s\n", inf->ai_addr->sa_data);
  printf("cannonname: %s\n", inf->ai_canonname);

  struct sockaddr_in addr = {
     inf->ai_family, //sa_family_t
     0,
  };
  //socket
  int sock_fd = socket(AF_INET, inf->ai_socktype, IPPROTO_ICMP);
  if(sock_fd == -1){
    fprintf(stderr, "sock_fd: %d\n", sock_fd);
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


  struct icmp_msg_t msg = {};
  msg.type = 8;
  msg.code = 0;
  msg.checksum = 0;
  msg.id = htons(getpid());
  msg.seqno = 1;
  

  struct timespec t0;
  rc = clock_gettime(CLOCK_MONOTONIC, &t0);
  if (rc == -1){
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  rc = send(sock_fd, (void *)&msg, sizeof(msg), 0);
  if (rc == -1){
    fprintf(stderr, "errno = %d\n", errno);
    perror("send");
    exit(EXIT_FAILURE);
  }

  printf("msg len: %zu bytes\nsent: %d bytes\nmsg body:", sizeof msg, rc);
  for (size_t i = 0; i < sizeof msg; i++)
      printf(" %02x", ((uint8_t *)&msg)[i]);
  printf("\n");

  //recv
  uint8_t buf[512];
  size_t recieved_count;
  recieved_count = recv(sock_fd, buf, 512, MSG_WAITALL);
  if (recieved_count == -1){
    perror("recv");
    exit(EXIT_FAILURE);
  }

  struct timespec t1;
  rc = clock_gettime(CLOCK_MONOTONIC, &t1);
  if (rc == -1){
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }

  double elapsed = (t1.tv_nsec - t0.tv_nsec)/1000000.0;
  printf("recv: %zu bytes after %f ms body:", recieved_count, elapsed);
  for (size_t i = 0; i <  recieved_count; i++)
      printf(" %02x", ((uint8_t *)&buf)[i]);
  printf("\n");

  return EXIT_SUCCESS;
}
