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
#include <limits.h>
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


int
main(int argc, char ** argv){
    int verbose = 0;
    int ttl = -1;
    int traceroute = 0;
    size_t pingc = INT64_MAX;
    const char * _d = argv[argc-1];
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i],"--ttl") == 0){
            ttl = atoi(argv[++i]); 
        }
        if(strcmp(argv[i],"--tr") == 0){
            traceroute = 1;
        }
        if(strcmp(argv[i],"--traceroute") == 0){
            traceroute = 1;
        }
        if(strcmp(argv[i], "-c") == 0){
            pingc = atoi(argv[++i]); 
        }
        if(strcmp(argv[i], "-v") == 0){
            verbose = 1;
        }
    }

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

    //socket
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock_fd == -1){
        fprintf(stderr, "sock_fd: %d\n", sock_fd);
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set ttl
    if(ttl == -1){
        if (traceroute)
            ttl = 1;
        else
            ttl = 128;
    }

    // Set timeout
    struct timeval tv = { .tv_sec = 2 };
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);


    struct icmp_msg_t msg = {};
    msg.type = 8;
    msg.code = 0;
    msg.id = htons(getpid());
    msg.seqno = htons(1);
    msg.checksum = inet_checksum(&msg, sizeof(msg));

    fprintf(stdout, "initial ttl: %d | traceroute? %d | pingc: %ld\n", ttl, traceroute, pingc);
    fprintf(stdout, "dest: %s\n", _d);
    int hopc = 0;
    while(pingc > 0){

        if (setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl) == -1)
            perror("setsockopt IP_TTL");

        struct timespec t0;
        rc = clock_gettime(CLOCK_MONOTONIC, &t0);
        if (rc == -1){
            perror("clock_gettime");
            exit(EXIT_FAILURE);
        }
        fprintf(stdout,"\n========================SENDING NEW========================\n");
        fprintf(stdout, "TTL: %d\t PINGS_REMAINING: %ld\n", ttl, pingc);
        rc = sendto(sock_fd, &msg, sizeof(msg), 0, (struct sockaddr *)&peer, dest_len);

        if (rc == -1){
            fprintf(stderr, "errno = %d\n", errno);
            perror("send");
            exit(EXIT_FAILURE);
        }

        if(verbose){
            printf("msg len: %zu bytes\nsent: %d bytes\nmsg body:\n", sizeof(msg), rc);
            for (size_t i = 0; i < sizeof(msg); i++){
                printf(" %02x", ((uint8_t *)&msg)[i]);
                if((i+1)%16 == 0){
                    printf("\n");
                }
            }
            printf("\n\n");
        }
            

        //recv
        uint8_t buf[1024];
        ssize_t recieved_count;
        struct sockaddr_in recv_addr;
        size_t running_recieved_count = 0;

        ip_header_t ip_header = {};
        struct icmp_msg_t icmp_res= {};

        while((recieved_count = recv(sock_fd, buf, 512, 0)) != -1){
            if(verbose){
                for(int i = 0; i < recieved_count; i++){
                    fprintf(stdout,"%02x ", buf[i]);
                    if((i+1)%16 == 0){
                        printf("\n");
                    }
                }
                fprintf(stdout, "\n");
            }


            if(running_recieved_count+=recieved_count < sizeof(ip_header)){
                continue;
            }

            memcpy(&ip_header,buf,sizeof(ip_header));
            size_t indexof_endiph = (ip_header.v_ihl & 0xF)*4;
            memcpy(&icmp_res, buf+indexof_endiph, sizeof(icmp_res));

            // Validate
            if (traceroute) {
                uint16_t reply_id;

                if (icmp_res.type == 0) {
                    memcpy(&reply_id, buf + indexof_endiph + 4, sizeof(reply_id));

                } else if (icmp_res.type == 11) {
                    size_t inner_ip_off = indexof_endiph + 8;
                    if ((size_t)recieved_count < inner_ip_off + 20) {
                        continue;
                    }
                    size_t inner_ihl = (buf[inner_ip_off] & 0xF) * 4;
                    size_t inner_icmp_off = inner_ip_off + inner_ihl;
                    if ((size_t)recieved_count < inner_icmp_off + 8) {
                        continue;
                    }
                    memcpy(&reply_id, buf + inner_icmp_off + 4, sizeof(reply_id));

                } else {
                    continue; // not part of our chain
                }

                if (reply_id != msg.id) {
                    continue;
                }
            }else if(icmp_res.id != msg.id){
               continue; 
            }

            char src_ip_buf[AF_MAX];
            char dest_ip_buf[AF_MAX];
            inet_ntop(AF_INET, &ip_header.src_addr, src_ip_buf, dest_len);
            inet_ntop(AF_INET, &ip_header.dest_addr, dest_ip_buf, dest_len);

            if(verbose){
                fprintf(stdout, "ip_res:\n"\
                        "\tversion %#x\n"\
                        "\theader-length = %#x\n"\
                        "\tfull_length = %d\n",
                        ip_header.v_ihl>>4,
                        ip_header.v_ihl & 0x7,
                        be16toh(ip_header.len)
                       );
            }
            fprintf(stdout, "ipv4_response:"\
                    "\tSRC: %s |"\
                    "\tDEST: %s\n",
                    src_ip_buf,
                    dest_ip_buf
                   );
            fprintf(stdout, "icmp_response:"\
                            "\tTYPE: %d |"\
                            "\tCODE: %d\n",
                            icmp_res.type,
                            icmp_res.code);
            if(be16toh(ip_header.len) >= running_recieved_count){
                break;
            }
        }


        struct timespec t1;
        rc = clock_gettime(CLOCK_MONOTONIC, &t1);
        if (rc == -1){
            perror("clock_gettime");
            exit(EXIT_FAILURE);
        }
        double elapsed = (t1.tv_nsec - t0.tv_nsec)/1000000.0;

        if(icmp_res.type == 0){
            printf("recieved: %zu bytes after %fms\n", running_recieved_count, elapsed);
            if(traceroute) break;
        }else if(icmp_res.type == 8){
            printf("recieved: %zu bytes after %fms\n", running_recieved_count, elapsed);
            ;//Todo fix the timer here
        }else if(icmp_res.type == 11 && traceroute){
            ;
            printf("recieved: %zu bytes after %fms\n", running_recieved_count, elapsed);
        }else{

            fprintf(stdout, "something else..see icmp_res.type!\n");
            break;
        }
        ttl++;
        pingc--;
        hopc++;
        if(!traceroute){
            sleep(1);
        }
    }
    if(traceroute){
        fprintf(stdout, "completed in %d hops\n", hopc);
    }

    return EXIT_SUCCESS;
}

