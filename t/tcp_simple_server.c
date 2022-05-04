
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv){
    int listen_sock, len, sock;
    if(argc < 2){
        printf("Usage : port\n");
        return -1;
    }
    in_port_t port = atoi(argv[1]);
    listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if(listen_sock < 0){
        perror("socket");
        return -1;
    }


    struct sockaddr_in6 saddr, caddr;
    saddr.sin6_family = AF_INET6;
    saddr.sin6_port = htons(port);
    saddr.sin6_addr = in6addr_any;

    if(bind(listen_sock, (struct sockaddr *) &saddr, sizeof(saddr))){
        perror("bind");
        return -1;
    }

    if(listen(listen_sock, 5)){
        perror("listen");
        return -1;
    }
    
    len = sizeof(caddr);

    sock = accept(listen_sock, (struct sockaddr *) &caddr, &len);
    if(sock < 0){
        perror("accept");
        return -1;
    }

    fprintf(stderr, "Connect :)\n");
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
    timeout.tv_sec = 100;

    while (1){
        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        FD_SET(sock , &readset);
        select(maxfd+1, &readset, &writeset, NULL, &timeout);
    }
    


}
