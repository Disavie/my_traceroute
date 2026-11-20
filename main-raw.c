#include <bits/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

struct icmp_msg_t {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;

  uint16_t id;
  uint16_t seqno;

  uint8_t payload[16];
};


static uint16_t inet_checksum(const void *buf, size_t len) {
    const uint16_t *p = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

#define HOST_NAME_MAX 512

int main(int argc, char ** argv){
  
  int rc = 0;

  char name[HOST_NAME_MAX];
  struct addrinfo *localinf;
  gethostname(name, HOST_NAME_MAX);
  rc =getaddrinfo(name, NULL, NULL, &localinf);

  char lip[INET_ADDRSTRLEN];
  struct sockaddr_in *sin = (struct sockaddr_in *)localinf->ai_addr;
  inet_ntop(AF_INET, &sin->sin_addr, lip, sizeof lip);
  printf("self host:%s\tip:%s\n", name, lip);
  freeaddrinfo(localinf);


  fprintf(stdout, "checking ip of: %s\n", argv[1]);
  struct addrinfo *inf = NULL;
  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_flags = AI_ADDRCONFIG |AI_CANONNAME;

  rc = getaddrinfo(argv[1], NULL, &hints, &inf);
  if(rc != 0){ //-2 -> name/service is unknown
    fprintf(stderr, "rc: %d\n", rc);
    perror("getaddrinfo");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in *peer = (struct sockaddr_in *)inf->ai_addr;
  char ssockip[INET_ADDRSTRLEN];  
  inet_ntop(AF_INET, &peer->sin_addr, ssockip, INET_ADDRSTRLEN);
  fprintf(stdout,"resolved peer: %s\n", ssockip);

  printf("is AF_INET?: %d\n", inf->ai_family == AF_INET);
  printf("SOCKET_RAW?: %d\n", inf->ai_socktype == SOCK_RAW);

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
  // Set ttl
  int ttl = 1;
  if (setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl) == -1)
      perror("setsockopt IP_TTL");
  // Set timeout
  struct timeval tv = { .tv_sec = 2 };
  setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);


  struct icmp_msg_t msg = {};
  msg.type = 8;
  msg.code = 0;
  msg.id = htons(getpid());
  msg.seqno = htons(1);
  msg.checksum = inet_checksum(&msg, sizeof(msg));
  

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

  printf("msg len: %zu bytes\nsent: %d bytes\nmsg body:\n", sizeof(msg), rc);
  for (size_t i = 0; i < sizeof(msg); i++)
      printf(" %02x", ((uint8_t *)&msg)[i]);
  printf("\n");

  //recv
  uint8_t buf[512];
  size_t recieved_count;
  recieved_count = recv(sock_fd, buf, 512, 0);
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
