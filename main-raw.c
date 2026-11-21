#include <bits/time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>

#define IP_RES_MAX 60
#define ICMP_RES_MAX 64

typedef struct {
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
}ip_header_t;

struct icmp_msg_t {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;

  uint16_t id;
  uint16_t seqno;

  uint8_t payload[16];
};

static uint16_t
inet_checksum(const void *buf, size_t len) {
    const uint16_t *p = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

#define HOST_NAME_MAX 512

int
main(int argc, char ** argv){
  int ttl = -1;
  const char * _d = argv[argc-1];
  for(int i = 0; i < argc; i++){
    if(strcmp(argv[i],"--ttl") == 0){
     ttl = atoi(argv[++i]); 
    }
  }
  fprintf(stdout, "ttl: %d\ndest: %s\n", ttl, _d);
  
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


  fprintf(stdout, "checking ip of: %s\n", _d);
  struct addrinfo *inf = NULL;
  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_flags = AI_ADDRCONFIG |AI_CANONNAME;

  rc = getaddrinfo(_d, NULL, &hints, &inf);
  if(rc != 0){ //-2 -> name/service is unknown
    fprintf(stderr, "rc: %d\n", rc);
    perror("getaddrinfo");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in peer;
  memcpy(&peer, inf->ai_addr, sizeof peer);
  socklen_t dest_len = inf->ai_addrlen;
  freeaddrinfo(inf);

  char ssockip[INET_ADDRSTRLEN];  
  inet_ntop(AF_INET, &peer.sin_addr , ssockip, INET_ADDRSTRLEN);
  fprintf(stdout,"resolved peer: %s\n", ssockip);

  printf("is AF_INET?: %d\n", inf->ai_family == AF_INET);
  printf("SOCKET_RAW?: %d\n", inf->ai_socktype == SOCK_RAW);

  //socket
  int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(sock_fd == -1){
    fprintf(stderr, "sock_fd: %d\n", sock_fd);
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // Set ttl
  if(ttl == -1){
    ttl = 128;
  }
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
  rc = sendto(sock_fd, &msg, sizeof(msg), 0, (struct sockaddr *)&peer, dest_len);

  if (rc == -1){
    fprintf(stderr, "errno = %d\n", errno);
    perror("send");
    exit(EXIT_FAILURE);
  }

  printf("msg len: %zu bytes\nsent: %d bytes\nmsg body:\n", sizeof(msg), rc);
  for (size_t i = 0; i < sizeof(msg); i++)
      printf(" %02x", ((uint8_t *)&msg)[i]);
  printf("\n\n");

  //recv
  uint8_t buf[1024];
  ssize_t recieved_count;
  struct sockaddr_in recv_addr;
  size_t running_recieved_count = 0;
  
  enum curr_header_type {
    IP, 
    ICMP, 
  };

  ip_header_t ip_header = {};
  struct icmp_msg_t icmp_res= {};
  
  int finished = 0;
  enum curr_header_type looking_at = IP;
  while((recieved_count = recv(sock_fd, buf, 512, 0)) != -1){
    for(int i = 0; i < recieved_count; i++)
      fprintf(stdout,"%02x ", buf[i]);

    memcpy(&ip_header,buf,sizeof(ip_header));
    //snprintf(res_ip,IP_RES_MAX," %02x", ((uint8_t *)&buf)[i]);
    fprintf(stdout, "ip version %#x\n", ip_header.v_ihl>>4);
    fprintf(stdout, "hlen %#x\n", ip_header.v_ihl & 0x7);
    fprintf(stdout, "full len %d\n", be16toh(ip_header.len));

    size_t indexof_endiph = (ip_header.v_ihl & 0x7)*4;
    memcpy(&icmp_res, buf+indexof_endiph, sizeof(icmp_res));
    fprintf(stdout, "icmp type %d\n", icmp_res.type);
    fprintf(stdout, "icmp code %d\n", icmp_res.code);
    running_recieved_count+=recieved_count;
    if(be16toh(ip_header.len) >= running_recieved_count){
      break;
    }

  }
  fprintf(stderr, "errno = %d\n", errno);
  perror("recv");

  struct timespec t1;
  rc = clock_gettime(CLOCK_MONOTONIC, &t1);
  if (rc == -1){
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }

  double elapsed = (t1.tv_nsec - t0.tv_nsec)/1000000.0;
  printf("recieved: %zu bytes after %f ms\n:", running_recieved_count, elapsed);
  return EXIT_SUCCESS;
}
