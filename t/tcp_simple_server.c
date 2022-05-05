
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
    int listen_sock, len, sock, ch, io_fd = 0, reply = 0;
    char *input_file = NULL;

    while((ch = getopt(argc, argv, "rf:")) != -1){
        switch (ch){
        case 'f':{
            input_file = optarg;
            break;
        }
        case 'r':{
            reply = 1;
            break;
        }
        default:
            break;
     }
    }
    argc -= optind;
    argv += optind;
    if(argc < 1){
        printf("Usage : port\n");
        return -1;
    }
    in_port_t port = atoi((--argc, *argv++));
    listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if(listen_sock < 0){
        perror("socket");
        return -1;
    }

    if(input_file){
        io_fd = open(input_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
        if(io_fd < 0){
            perror("open");
        }
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
                write(io_fd, buf, n_rec);
            }
            if(reply){
                n_rec = write(sock, "ack", 4);
            }
        }
    }
    printf("No more connection, received %ld bytes \n", received);
}
