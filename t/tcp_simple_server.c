#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/tcp.h>

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


int main(int argc, char **argv){
    int listen_sock, sock, ch, io_fd = 0, reply = 0;
    char *input_file = NULL;
    int family = AF_INET6;

    while((ch = getopt(argc, argv, "rf:4")) != -1){
        switch (ch){
        case 'f':{
            input_file = optarg;
            break;
        }
        case 'r':{
            reply = 1;
            break;
        }
        case '4':{
            family = AF_INET;
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
    listen_sock = socket(family, SOCK_STREAM, 0);
    if(listen_sock < 0){
        perror("socket");
        return -1;
    }
    int on = 1;
    int qlen = 5;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return 1;
    }
    if (setsockopt(listen_sock, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) != 0) {
        perror("setsockopt(TCP_FASTOPEN) failed");
    }

    struct addrinfo hints, *res;
    struct sockaddr_storage saddr, caddr;
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

    if(input_file){
        io_fd = open(input_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
        if(io_fd < 0){
            perror("open");
        }
    }

    if(bind(listen_sock, (struct sockaddr *) &saddr, sizeof(saddr))){
        perror("bind");
        return -1;
    }

    if(listen(listen_sock, 5)){
        perror("listen");
        return -1;
    }
    
    socklen_t len = sizeof(caddr);

    sock = accept(listen_sock, (struct sockaddr *) &caddr, &len);
    if(sock < 0){
        perror("accept");
        return -1;
    }

    char *hello = "hello";
    int ret = write(sock, hello, 6);
    if(ret < 0){
        perror("write");
        return -1;
    }
      
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
            if(input_file){
                ret = write(io_fd, buf, n_rec);
                if(ret < 0){
                    perror("write");
                }
            }
            if(reply){
                n_rec = write(sock, "ack", 4);
            }
        }
    }
    close(sock);
    close(listen_sock);
}
