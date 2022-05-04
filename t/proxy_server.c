#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#if PICOTLS_USE_BROTLI
#include "brotli/decode.h"
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"
#if PICOTLS_USE_BROTLI
#include "picotls/certificate_compression.h"
#endif
#include "util.h"

typedef enum tunnel_message_type_t {
    TCP_CONNECT,
    TCP_CONNECT_OK,
    ERROR,
    END,
    
    enum_sentinel = 255UL
} tunnel_message_type;

typedef enum tcpls_conn_state_t{
    PROXY_CLOSED,
    PROXY_WAITING_TCP_CONNECT,
    PROXY_OPENED
} tcpls_conn_state;

typedef struct st_tcp_conn tcp_conn_t;

typedef struct st_tcpls_conn{
    int state;
    int socket;
    int transportid;
    list_t *streams;
    streamid_t streamid;
    tcpls_buffer_t *recvbuf;
    int buf_off_val;
    tcpls_t *tcpls;
    tcp_conn_t *tcp;
} tcpls_conn_t;

struct st_tcp_conn{
    int socket;
    tcpls_conn_t *tcpls_conn;
};

typedef struct st_internal_data{
    list_t *our_addrs;
    list_t *our_addrsV6;

    list_t *tcp_conns;
    list_t *tcpls_conns;
    list_t *streamlist;
} internal_data_t;

static void free_data(internal_data_t *data){

}

/** Temporaly to ease devopment. Later on: merge with handle_connection and make
 * TCPLS supports TLS 1.3's integration tests */

static void tcpls_add_ips(tcpls_t *tcpls, struct sockaddr_storage *sa_our,
    struct sockaddr_storage *sa_peer, int nbr_our, int nbr_peer) {
  int settopeer = tcpls->tls->is_server;
  for (int i = 0; i < nbr_our; i++) {
    if (sa_our[i].ss_family == AF_INET)
      tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&sa_our[i], 1, settopeer, 1);
    else
      tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&sa_our[i], 0, settopeer, 1);
  }
  int is_primary = 0;
  for (int i = 0; i < nbr_peer; i++) {
    if (sa_peer[i].ss_family == AF_INET) {
      if (i == nbr_peer-1)
        is_primary = 1;
      else
        is_primary = 0;
      tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&sa_peer[i], is_primary, 0, 0);
    }
    else
      tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&sa_peer[i], 0, 0, 0);
  }
}

static int handle_stream_event(tcpls_t *tcpls, tcpls_event_t event,
    streamid_t streamid, int transportid, void *cbdata) {
  internal_data_t *data = (internal_data_t *) cbdata;
  list_t *conn_tcpls_l = data->tcpls_conns;
  tcpls_conn_t *conn_tcpls;
  
  struct timeval now;
  struct tm *tm;
  gettimeofday(&now, NULL);
  tm = localtime(&now.tv_sec);
  char timebuf[32], usecbuf[7];
  strftime(timebuf, 32, "%H:%M:%S", tm);
  strcat(timebuf, ".");
  sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
  strcat(timebuf, usecbuf);
  fprintf(stderr, "%s Stream event %d\n", timebuf, event);
  switch (event) {
    case STREAM_OPENED:
    case STREAM_NETWORK_RECOVERED:
      if (event == STREAM_OPENED)
        fprintf(stderr, "Handling STREAM_OPENED callback %d \n", transportid);
      else
        fprintf(stderr, "Handling STREAM_NETWORK_RECOVERED callback\n");
      for (int i = 0; i < conn_tcpls_l->size; i++) {
        conn_tcpls = list_get(conn_tcpls_l, i);
        if (conn_tcpls->tcpls == tcpls && conn_tcpls->transportid == transportid) {
          conn_tcpls->streamid = streamid;
          fprintf(stderr, "Stream id of connection %d is now %u\n", transportid, streamid);
          break;
        } 
      }
      break;
      /** currently assumes 2 streams */
    case STREAM_CLOSED:
    case STREAM_NETWORK_FAILURE:
      if (event == STREAM_CLOSED)
        fprintf(stderr, "Handling STREAM_CLOSED callback\n");
      else
        fprintf(stderr, "Handling STREAM_NETWORK_FAILURE callback\n");
      for (int i = 0; i < conn_tcpls_l->size; i++) {
        conn_tcpls = list_get(conn_tcpls_l, i);
        if (tcpls == conn_tcpls->tcpls && conn_tcpls->transportid == transportid && conn_tcpls->streamid == streamid) {
          fprintf(stderr, "Woh! we're stopping to write on the connection linked to transportid %d streamid %u\n", transportid, streamid);
        }
      }
    default: break;
  }
  return 0;
}

static int handle_connection_event(tcpls_t *tcpls, tcpls_event_t event, int
    socket, int transportid, void *cbdata) {
  internal_data_t *data = (internal_data_t *) cbdata;
  list_t *conntcpls = data->tcpls_conns;
  struct timeval now;
  struct tm *tm;
  gettimeofday(&now, NULL);
  tm = localtime(&now.tv_sec);
  char timebuf[32], usecbuf[7];
  strftime(timebuf, 32, "%H:%M:%S", tm);
  strcat(timebuf, ".");
  sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
  strcat(timebuf, usecbuf);
  fprintf(stderr, "%s Connection event %d\n", timebuf, event);
  switch (event) {
    case CONN_FAILED:
      {
        fprintf(stderr, "Received a CONN_FAILED on socket %d\n", socket);
        tcpls_conn_t *ctcpls;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->tcpls == tcpls && ctcpls->socket == socket && ctcpls->transportid == transportid) {
            ctcpls->state = PROXY_CLOSED;
            break;
          }
        }
      }
      break;
    case CONN_OPENED:
      {
        fprintf(stderr, "Received a CONN_OPENED; adding transportid %d to the socket %d\n", transportid, socket);
        tcpls_conn_t *ctcpls;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->tcpls == tcpls && ctcpls->socket == socket) {
            ctcpls->transportid = transportid;
            ctcpls->state = PROXY_WAITING_TCP_CONNECT;
            break;
          }
        }
      }
      break;
    case CONN_CLOSED:
      {
        fprintf(stderr, "Received a CONN_CLOSED; removing the connection linked to  socket %d\n", socket);
        tcpls_conn_t *ctcpls;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->tcpls == tcpls && ctcpls->socket == socket && ctcpls->transportid == transportid) {
            ctcpls->socket = 0;
            ctcpls->state = PROXY_CLOSED;
          }
        }
      }
      break;
    default: break;
  }
  return 0;
}

static int handle_tcpls_read(tcpls_t *tcpls, int socket, tcpls_buffer_t *buf, list_t *streamlist, list_t *conn_tcpls) {

  int ret;
  if (!ptls_handshake_is_complete(tcpls->tls) && tcpls->tls->state <
      PTLS_STATE_SERVER_EXPECT_FINISHED) {
    ptls_handshake_properties_t prop = {NULL};
    memset(&prop, 0, sizeof(prop));
    prop.socket = socket;
    if (tcpls->enable_failover && tcpls->tls->is_server) {
      tcpls_set_user_timeout(tcpls, 0, 250, 0, 1, 1);
    }
    if ((ret = tcpls_handshake(tcpls->tls, &prop)) != 0) {
      if (ret == PTLS_ERROR_HANDSHAKE_IS_MPJOIN) {
        return ret;
      }
      fprintf(stderr, "tcpls_handshake failed with ret %d\n", ret);
    }
    else if (ret == 0 && tcpls->tls->is_server) {
      // set this conn as primary
      return -2;
    }
    return 0;
  }
  struct timeval timeout;
  memset(&timeout, 0, sizeof(timeout));
  int *init_sizes;
  if (tcpls->tls->is_server) {
    init_sizes = calloc(conn_tcpls->size, sizeof(int));
  }
  else {
    init_sizes = calloc(streamlist->size ? streamlist->size : 1, sizeof(int));
  }
  if (buf->bufkind == AGGREGATION)
    init_sizes[0] = buf->decryptbuf->off;
  else {
    streamid_t *streamid;
    ptls_buffer_t *decryptbuf;
    if (!tcpls->tls->is_server) {
      for (int i = 0; i < streamlist->size; i++) {
        streamid = list_get(streamlist, i);
        decryptbuf = tcpls_get_stream_buffer(buf, *streamid);
        if(decryptbuf){
          init_sizes[i] = decryptbuf->off;
        }
      }
    }
    else {
      /*server read */
      tcpls_conn_t *conn;
      for (int i = 0; i < conn_tcpls->size; i++) {
        conn = list_get(conn_tcpls, i);
        if (conn->tcpls == tcpls) {
          decryptbuf = tcpls_get_stream_buffer(buf, conn->streamid);
          if (decryptbuf) {
            init_sizes[i] = decryptbuf->off;
          }
        }
      }
    }
  }
  while ((ret = tcpls_receive(tcpls->tls, buf, &timeout)) == TCPLS_HOLD_DATA_TO_READ)
    ;
  if (ret < 0) {
    fprintf(stderr, "tcpls_receive returned %d\n",ret);
  }
  if (buf->bufkind == AGGREGATION)
    ret = buf->decryptbuf->off-init_sizes[0];
  else {
    streamid_t *wtr_streamid, *streamid;
    ptls_buffer_t *decryptbuf;
    for (int i = 0; i < buf->wtr_streams->size; i++) {
      wtr_streamid = list_get(buf->wtr_streams, i);
      if (!tcpls->tls->is_server) {
        for (int j = 0; j < streamlist->size; j++) {
          streamid = list_get(streamlist, j);
          if (*wtr_streamid == *streamid) {
            decryptbuf = tcpls_get_stream_buffer(buf, *streamid);
            if (decryptbuf) {
              ret += decryptbuf->off-init_sizes[j];
              j = streamlist->size;
            }
          }
        }
      }
      else {
        tcpls_conn_t *conn;
        for (int j = 0; j < conn_tcpls->size; j++) {
          conn = list_get(conn_tcpls, j);
          if (conn->tcpls == tcpls && *wtr_streamid == conn->streamid) {
             decryptbuf = tcpls_get_stream_buffer(buf, *wtr_streamid);
             if (decryptbuf) {
               ret += decryptbuf->off - init_sizes[j];
               j = conn_tcpls->size;
             }
          }
        }
      }
    }
  }
  return ret;
}

static int handle_tcp_connect(internal_data_t *data, tcpls_conn_t *conn, uint8_t *message, size_t message_len){
    if(message_len < 20){
      fprintf(stderr, "Message is too short length\n");
      return -1;
    }
    tunnel_message_type type = message[0];
    if(type != TCP_CONNECT){
      fprintf(stderr, "Message isn't a TCP Connect\n");
      return -1;
    }
    uint8_t tlv_len = message[1];
    if(tlv_len != 18){
      fprintf(stderr, "Invalid message length\n");
      return -1;
    }
    in_port_t port = *(in_port_t *) &message[2];
    struct in6_addr addr = *(struct in6_addr *) &message[4];
    struct sockaddr_in6 peer_addr;
    memset(&peer_addr, 0, sizeof(struct sockaddr_in6));
    peer_addr.sin6_family = AF_INET6;
    peer_addr.sin6_port = port;
    peer_addr.sin6_addr = addr;

    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, addr_str, INET6_ADDRSTRLEN);

    if(connect(sock, (struct sockaddr *) &peer_addr, sizeof(struct sockaddr_in6)) != 0){
        fprintf(stderr, "Fail to establish TCP tunnel to %s\n", addr_str);

        return -1;
    }
    fprintf(stderr, "Established TCP tunnel to %s\n", addr_str);
    tcp_conn_t tcp_new;
    tcp_new.socket = sock;
    tcp_new.tcpls_conn = conn;
    list_add(data->tcp_conns, &tcp_new);
    conn->tcp = &tcp_new;

    uint8_t ok_message[4];
    ok_message[0] = TCP_CONNECT_OK;
    ok_message[1] = 0;
    ok_message[2] = END;
    ok_message[3] = 0;
    int ret;
    while((ret = tcpls_send(conn->tcpls->tls, conn->streamid, ok_message, 4)) == TCPLS_CON_LIMIT_REACHED){

    }
    if(ret != 0) {
      fprintf(stderr, "tcpls_send returned %d for sending on streamid %u\n",
          ret, conn->streamid);
      return -1;
    } 

    conn->state = PROXY_OPENED;
    return 0;
}

static int handle_tcp_forward(internal_data_t *data, tcp_conn_t *conn_tcp, uint8_t *message, size_t message_len){
    fprintf(stderr, "forwarding from TCP %ld bytes of data : %s", message_len, message);
    int ret = write(conn_tcp->socket, message, message_len);
    if(ret < 0){
        fprintf(stderr, "failed to forward message\n");

        return ret;
    }
    return 0;
}

static int handle_tcp_read(internal_data_t *data, tcp_conn_t *conn_tcp){
    static const size_t block_size = PTLS_MAX_ENCRYPTED_RECORD_SIZE;
    uint8_t buf[block_size];
    int to_send = read(conn_tcp->socket,buf, block_size);
    if(to_send < 0){
        perror("read");
        return -1;
    }
    fprintf(stderr, "forwarding from TCPLS %d bytes of data : %s", to_send, buf);
    int ret;
    tcpls_conn_t *tcpls_conn = conn_tcp->tcpls_conn;
    while ((ret = tcpls_send(tcpls_conn->tcpls->tls, tcpls_conn->streamid, buf, to_send)) == TCPLS_CON_LIMIT_REACHED){
        /* wait conn limit */
    }
    if(ret != 0){
      fprintf(stderr, "tcpls_send returned %d for sending on streamid %u\n",
          ret, tcpls_conn->streamid);
      return -1;
    }
    return 0;
}

static int handle_proxy_server(internal_data_t *data, fd_set *readset, fd_set *writeset){
    int ret = 1;
    
    tcpls_conn_t *conn;
    for(int i = 0 ; i < data->tcpls_conns->size ; i++){
        conn = list_get(data->tcpls_conns, i);
        if(FD_ISSET(conn->socket, readset) && conn->state > CLOSED ){
            ret = handle_tcpls_read(conn->tcpls, conn->socket, conn->recvbuf, NULL, data->tcpls_conns);
            if(ret == -2){
                fprintf(stderr, "Primary connection connected\n");
                /*streamid_t streamid = tcpls_stream_new(conn->tcpls->tls, NULL, (struct sockaddr*) &conn->tcpls->v6_addr_llist->addr);
                fprintf(stderr, "Sending a STREAM_ATTACH on the new path\n");
                if (tcpls_streams_attach(conn->tcpls->tls, 0, 1) < 0)
                  fprintf(stderr, "Failed to attach stream %u\n", streamid);*/
                return 0;
            } else if(ret < 0) {
              fprintf(stderr, "Read failed %d\n", ret);
            }
            if(ptls_handshake_is_complete(conn->tcpls->tls)){
              if(!conn->streamid){ 
                ret = tcpls_send(conn->tcpls->tls, 0, "hello", 6);
                if(ret < 0){
                  fprintf(stderr, "tcpls_send failed %d\n", ret);
                }
                fprintf(stderr, "Brute force stream creation\n");
              }

                ptls_buffer_t *buf = tcpls_get_stream_buffer(conn->recvbuf, conn->streamid);
                if(!buf){
                  fprintf(stderr, "Failed to find buffer\n");
                }
                if(conn->state == PROXY_WAITING_TCP_CONNECT){
                    if(buf){
                        fprintf(stderr, "Handling a TCP Connect\n");
                        ret = handle_tcp_connect(data, conn,buf->base, buf->off);
                        buf->off = 0;
                    }
                } else if(conn->state == PROXY_OPENED){
                    ret = handle_tcp_forward(data, conn->tcp, buf->base, buf->off);
                    buf->off = 0;
                }
            }
        }
    }

    tcp_conn_t *conn_tcp;
    for(int i = 0 ; i < data->tcp_conns->size ; i++){
        conn_tcp = list_get(data->tcp_conns, i);
        if(FD_ISSET(conn_tcp->socket, readset)){
            ret = handle_tcp_read(data, conn_tcp);
        }
    }

    return ret;
}

static int start_server(struct sockaddr_storage *ours_sockaddr, int nbr_addr, ptls_context_t *ctx, ptls_handshake_properties_t *hsprop, internal_data_t *data){
    int listen_socks[nbr_addr];
    data->tcpls_conns = new_list(sizeof(tcpls_conn_t), 2);
    data->tcp_conns = new_list(sizeof(tcp_conn_t), 2);
    data->streamlist = new_list(sizeof(tcpls_stream_t), 2);

    //TODO Callbacks
    ctx->connection_event_cb = &handle_connection_event;
    ctx->stream_event_cb = &handle_stream_event;

    ctx->cb_data = data;

    socklen_t sa_len;
    int on = 1;
    int qlen = 5;

    for(int i = 0 ; i < nbr_addr ; i++){
        if(ours_sockaddr[i].ss_family == AF_INET){
            if((listen_socks[i] = socket(AF_INET, SOCK_STREAM, 0)) == -1){
                perror("socket(2) failed");
                return 1;
            }
        } else {
            if((listen_socks[i] = socket(AF_INET6, SOCK_STREAM, 0)) == -1){
                perror("socket(2) failed");
                return 1;
            }
        }
        if (setsockopt(listen_socks[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            return 1;
        }
        if (setsockopt(listen_socks[i], SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) != 0) {
            perror("setsockopt(TCP_FASTOPEN) failed");
        }
        if (ours_sockaddr[i].ss_family == AF_INET)
            sa_len = sizeof(struct sockaddr_in);
        else
            sa_len = sizeof(struct sockaddr_in6);
        if (bind(listen_socks[i], (struct sockaddr*) &ours_sockaddr[i], sa_len) != 0) {
            perror("bind(2) failed");
            return 1;
        }
        if (listen(listen_socks[i], SOMAXCONN) != 0) {
            perror("listen(2) failed");
            return 1;
        }
        fcntl(listen_socks[i], F_SETFL, O_NONBLOCK);    
    } 

    fd_set readset, writeset;
    int maxfd = 0;
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    tcpls_conn_t *conn;
    tcp_conn_t *proxy_conn;
    while(1){
        do {
            timeout.tv_sec = 100;
            FD_ZERO(&readset);
            FD_ZERO(&writeset);
            /** put all listeners in the read set */
            for (int i = 0; i < nbr_addr; i++) {
                FD_SET(listen_socks[i], &readset);
                if (maxfd < listen_socks[i])
                    maxfd = listen_socks[i];
            }
            /** put all tcp connections within the read set*/
            for (int i = 0; i < data->tcp_conns->size ; i++){
                proxy_conn = list_get(data->tcp_conns, i);
                FD_SET(proxy_conn->socket, &readset);
            }
            /** put all tcpls connections within the read set, and the write set if
             * they want to write */
            for (int i = 0; i < data->tcpls_conns->size; i++) {
                conn = list_get(data->tcpls_conns, i);
                if (conn->state > CLOSED) {
                    FD_SET(conn->socket , &readset);
                    if (maxfd < conn->socket)
                    maxfd = conn->socket;
                }
            }
            /*fprintf(stderr, "waiting for connection or r/w event...\n");*/
        } while (select(maxfd+1, &readset, &writeset, NULL, &timeout) == -1);
        /** Check first we have a listen() connection */
        for (int i = 0; i < nbr_addr; i++) {
            if (FD_ISSET(listen_socks[i], &readset)) {
                struct sockaddr_storage ss;
                socklen_t slen = sizeof(ss);
                int new_conn = accept(listen_socks[i], (struct sockaddr *)&ss, &slen);
                if (new_conn < 0) {
                    perror("accept");
                }
                else if (new_conn > FD_SETSIZE)
                    close(new_conn);
                else {
                    fprintf(stderr, "Accepting a new connection\n");
                    tcpls_t *new_tcpls = tcpls_new(ctx,  1);
                    new_tcpls->enable_multipath = 1;
                    tcpls_conn_t conntcpls;
                    memset(&conntcpls, 0, sizeof(conntcpls));
                    conntcpls.socket = new_conn;
                    conntcpls.tcpls = new_tcpls;
                    conntcpls.recvbuf = tcpls_stream_buffers_new(conntcpls.tcpls, 2);

                    /** ADD our ips  -- This might worth to be ctx and instance-based?*/
                    tcpls_add_ips(new_tcpls, ours_sockaddr, NULL, nbr_addr, 0);
                    list_add(data->tcpls_conns, &conntcpls);
                    if (tcpls_accept(new_tcpls, conntcpls.socket, NULL, 0) < 0)
                    fprintf(stderr, "tcpls_accept returned -1\n");
                } 
           }
        }
        //Handle data 
        if(handle_proxy_server(data, &readset, &writeset) < 0){
            //goto Exit;
        }
    }

    Exit:
        free_data(data);
        exit(0);
}


int main(int argc, char **argv){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    #if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
    #endif

    res_init();
    ptls_key_exchange_algorithm_t *key_exchanges[128] = {NULL};
    ptls_cipher_suite_t *cipher_suites[128] = {NULL};
    ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, cipher_suites};
    ptls_handshake_properties_t hsprop = {{{{NULL}}}};

    int ch;
    char *host, *port;
    internal_data_t data = {NULL};

    data.our_addrsV6 = new_list(40, 2);
    data.our_addrs = new_list(16, 2);
                

    while ((ch = getopt(argc, argv, "c:k:z:Z:")) != -1){
        switch(ch){
            case 'c':{
                if (ctx.certificates.count != 0) {
                    fprintf(stderr, "-C/-c can only be specified once\n");
                    return 1;
                }
                load_certificate_chain(&ctx, optarg);
                break;
            }
            case 'k':{
                load_private_key(&ctx, optarg);
                break;
            }
            case 'z':{
                char addr[16];
                int addrlen = strlen(optarg);
                if(addrlen > 15){
                    fprintf(stderr, "Not a valid addr: %s\n", optarg);
                    exit(1);
                }
                memcpy(addr, optarg, addrlen);
                addr[addrlen] = '\0';
                list_add(data.our_addrs,addr);
                break;
            }
            case 'Z':{
                char addr[40];
                int addrlen = strlen(optarg);
                if(addrlen > 39){
                    fprintf(stderr, "Not a valid addr: %s\n", optarg);
                    exit(1);
                }
                memcpy(addr, optarg, addrlen);
                addr[addrlen] = '\0';
                list_add(data.our_addrsV6,addr);
                break;
            }
            default:{
                exit(1);
            }
        }
    }
    if(ctx.certificates.count == 0){
        fprintf(stderr, "Plese provide a certificate and a key\n");
    }
    setup_session_cache(&ctx);
    if (key_exchanges[0] == NULL)
        key_exchanges[0] = &ptls_openssl_secp256r1;
    if (cipher_suites[0] == NULL) {
        size_t i;
        for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
        cipher_suites[i] = ptls_openssl_cipher_suites[i];
    }

    argc -= optind;
    argv += optind;
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        return 1;
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    int idx = 0;
    int nbr_addrs = data.our_addrs->size + data.our_addrsV6->size + 1;
    struct sockaddr_storage ours_sockaddr[nbr_addrs];
    socklen_t sa_len;
    char *addr;
    for (int i = 0; i < data.our_addrs->size; i++) {
        addr = list_get(data.our_addrs, i);
        if (resolve_address((struct sockaddr *)&ours_sockaddr[i], &sa_len, addr, port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0){
            fprintf(stderr, "Failed to resolve addr: %s\n", addr);
            exit(1);
        }
    }
    idx += data.our_addrs->size;
    for (int i = 0; i < data.our_addrsV6->size; i++) {
        addr = list_get(data.our_addrsV6, i);
        if (resolve_address((struct sockaddr *)&ours_sockaddr[i+idx], &sa_len, addr, port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0){
            fprintf(stderr, "Failed to resolve addr: %s\n", addr);
            exit(1);
        }
    }
    idx += data.our_addrsV6->size;
    if (resolve_address((struct sockaddr*)&ours_sockaddr[idx], &sa_len, host, port,0, SOCK_STREAM, IPPROTO_TCP) != 0){
        fprintf(stderr, "Failed to resolve addr: %s\n", host);        
        exit(1);
    }

    return start_server(ours_sockaddr, nbr_addrs, &ctx, &hsprop, &data);
}