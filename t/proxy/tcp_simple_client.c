#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/tcp.h>
#include <sys/time.h>

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef enum performance_test_t{
    T_GOODPUT,
    T_LATENCY,
    T_REQUESTS,
    T_NOTEST
} performance_test;

static int handle_latency_test(int sock, struct timeval old){
    fd_set readset;
    int maxfd = sock;
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    static const size_t block_size = 16384 + 256;
    uint8_t buf[block_size];
    while (1){
        timeout.tv_sec = 10;
        FD_ZERO(&readset);
        FD_SET(sock , &readset);
        select(maxfd+1, &readset, NULL, NULL, &timeout);
        if(FD_ISSET(sock, &readset)){
            int n_rec = read(sock, buf, block_size );
            if(n_rec > 0){
                struct timeval now;
                gettimeofday(&now, NULL);
                time_t sec = now.tv_sec - old.tv_sec;
                suseconds_t usec = now.tv_usec - old.tv_usec;
                if(usec < 0){
                usec += 1000000;
                sec -= 1;
                }
                printf("latency : %ld.%06ld\n", sec,usec);
                close(sock);
                return 0;
            }
        }
    }
}

static int handle_goodput_test(int sock, struct timeval old){
    fd_set readset;
    int maxfd = sock;
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    static const size_t block_size = 4 *(16384 + 256);
    uint8_t buf[block_size];
    long total_received = 0;
    while (1){
        timeout.tv_sec = 10;
        FD_ZERO(&readset);
        FD_SET(sock , &readset);
        select(maxfd+1, &readset, NULL, NULL, &timeout);
        if(FD_ISSET(sock, &readset)){
            int n_rec = read(sock, buf, block_size );
            if(n_rec < 0){
                perror("received failed");
            }
            total_received += n_rec;
            if(total_received >= 10000000000){
                struct timeval now;
                gettimeofday(&now, NULL);
                time_t sec = now.tv_sec - old.tv_sec;
                suseconds_t usec = now.tv_usec - old.tv_usec;
                if(usec < 0){
                usec += 1000000;
                sec -= 1;
                }
                printf("goodput :%ld bytes %ld.%06ld sec \n", total_received,sec,usec);
                close(sock);
                return 0;
            }
        }
    }
}

static int handle_requests_test(int sock, struct timeval old, int response_size){
    fd_set readset, writeset;
    int maxfd = sock;
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    uint8_t buf[response_size];
    long total_requests = 0;
    int acked = 1;
    int received = 0;
    int ret;
    while (1){
        timeout.tv_sec = 1;
        FD_ZERO(&readset);
        FD_SET(sock , &readset);
        FD_SET(sock , &writeset);
        ret = select(maxfd+1, &readset, &writeset, NULL, &timeout);
        if(acked){
            uint8_t req[800];
            int ret = write(sock, req, 800);
            acked = 0;
            received = 0;
            if(ret < 0){
                perror("send");
            }
        }
        if(FD_ISSET(sock, &readset)){
            int n_rec = read(sock, buf, response_size );
            if(n_rec < 0){
                perror("received failed");
            }
            received += n_rec;
            if(received >= response_size){
                total_requests += 1;
                acked = 1;
            }
        }
        if(total_requests >= 1000){
            struct timeval now;
            gettimeofday(&now, NULL);
            time_t sec = now.tv_sec - old.tv_sec;
            suseconds_t usec = now.tv_usec - old.tv_usec;
            if(usec < 0){
            usec += 1000000;
            sec -= 1;
            }
            printf("requests :%ld %ld.%06ld sec \n", total_requests,sec,usec);
            close(sock);
            return 0;
        }
    }
}

int main(int argc, char **argv){
    int sock, ch, response_size = 0;
    int family = AF_INET6;
    performance_test test = T_NOTEST;
    struct timeval test_start_timer;

    while((ch = getopt(argc, argv, "t:4r:")) != -1){
        switch (ch){
        case '4':{
            family = AF_INET;
            break;
        }
        case 't':{
          if(strcasecmp(optarg, "goodput") == 0)
            test = T_GOODPUT;
          else if(strcasecmp(optarg, "latency") == 0)
            test = T_LATENCY;
          else if(strcasecmp(optarg, "requests") == 0)
            test = T_REQUESTS;            
          else{
            fprintf(stderr, "Unknown test: %s\n", optarg);
          }
          break;
        }
        case 'r':{
            response_size = atoi(optarg);
            break;
        }
        default:
            break;
     }
    }
    argc -= optind;
    argv += optind;
    if(argc != 2){
        printf("Usage : host port\n");
        return -1;
    }
    char *host =  (--argc, *argv++);
    char *port =  (--argc, *argv++);
    sock = socket(family, SOCK_STREAM, 0);
    if(sock < 0){
        perror("socket");
        return -1;
    }
    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return 1;
    }

    struct addrinfo hints, *res;
    struct sockaddr_storage saddr;
    int err;


    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(&saddr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if(connect(sock, (struct sockaddr *) &saddr, sizeof(saddr))){
        perror("connect");
        return -1;
    }

    switch(test){
        case T_LATENCY:{
            gettimeofday(&test_start_timer, NULL);
            return handle_latency_test(sock, test_start_timer);
            break;
        }
        case T_GOODPUT:{
            gettimeofday(&test_start_timer, NULL);
            return handle_goodput_test(sock, test_start_timer);
            break;
        }
        case T_REQUESTS:{
            gettimeofday(&test_start_timer, NULL);
            return handle_requests_test(sock, test_start_timer, response_size);
            break;
        }
        case T_NOTEST:{
            break;
        }
    }
    
    int ret = 1;
    fd_set readset, writeset;
    int maxfd = sock;
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    static const size_t block_size = 16384 + 256;
    uint8_t buf[block_size];
    long received = 0;
    while (ret > 0){
        timeout.tv_sec = 10;
        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        FD_SET(sock , &readset);
        ret = select(maxfd+1, &readset, &writeset, NULL, &timeout);
        if(FD_ISSET(sock, &readset)){
            int n_rec = read(sock, buf, block_size );
            if(n_rec == 0){
                break;
            }
            received += n_rec;
        }
    }
    close(sock);
}
