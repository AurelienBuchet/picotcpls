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
#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"
#include "util.h"

typedef enum performance_test_t{
    T_THROUGHPUT,
    T_LATENCY,
    T_NOTEST
} performance_test;

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

typedef struct st_tcpls_conn{
    int state;
    int socket;
    int transportid;
    list_t *streams;
    streamid_t streamid;
    tcpls_buffer_t *recvbuf;
    int buf_off_val;
    tcpls_t *tcpls;
} tcpls_conn_t;

typedef struct st_internal_data{
    list_t *proxy_addrs;
    list_t *proxy_addrsV6;

    struct sockaddr_in6 *peer_addr;

    list_t *tcpls_conns;
    list_t *streamlist;

    struct timeval test_start_timer;
} internal_data_t;

int verbose = 0;

static void sig_handler(int signo) {
  if (signo == SIGPIPE) {
    fprintf(stderr, "Catching a SIGPIPE error\n");
  }
}

static void free_data(internal_data_t *data){
  list_free(data->proxy_addrs);
  list_free(data->proxy_addrsV6);
  list_free(data->tcpls_conns);
  list_free(data->streamlist);
  free(data->peer_addr);
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
  if(verbose){
    fprintf(stderr, "%s Connection event %d\n", timebuf, event);
  }
  switch (event) {
    case CONN_FAILED:
      {
        if(verbose){
          fprintf(stderr, "Received a CONN_FAILED on socket %d\n", socket);
        }
        tcpls_conn_t *ctcpls;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->tcpls == tcpls && ctcpls->socket == socket && ctcpls->transportid == transportid) {
            ctcpls->state = FAILED;
            tcpls_buffer_free(ctcpls->tcpls, ctcpls->recvbuf);
            list_remove(conntcpls, ctcpls);
            break;
          }
        }
      }
      break;
    case CONN_OPENED:
      {
        if(verbose){
          fprintf(stderr, "Received a CONN_OPENED;\n");
        }
        tcpls_conn_t *ctcpls;
        int found = 0;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->tcpls == tcpls && ctcpls->socket == socket) {
            found = 1;
            ctcpls->transportid = transportid;
            ctcpls->state = CONNECTED;
            break;
          }
        }
        if(!found){
          tcpls_conn_t conn_new;
          conn_new.state = CONNECTED;
          conn_new.socket = socket;
          conn_new.transportid = transportid;
          conn_new.tcpls = tcpls;
          list_add(conntcpls, &conn_new);
          if(verbose){
            fprintf(stderr, "adding transportid %d to the socket %d\n", transportid, socket);
          }
        }
      }
      break;
    case CONN_CLOSED:
      {
        if(verbose){
          fprintf(stderr, "Received a CONN_CLOSED; removing the connection linked to socket %d\n", socket);
        }
        tcpls_conn_t *ctcpls;
        for (int i = 0; i < conntcpls->size; i++) {
          ctcpls = list_get(conntcpls, i);
          if (ctcpls->tcpls == tcpls && ctcpls->socket == socket && ctcpls->transportid == transportid) {
            ctcpls->socket = 0;
            ctcpls->state = CLOSED;
          }
        }
      }
      break;
    default: break;
  }
  return 0;
}

static int handle_client_stream_event(tcpls_t *tcpls, tcpls_event_t event, streamid_t streamid,
    int transportid, void *cbdata) {
  internal_data_t *data = (internal_data_t *) cbdata;
  struct timeval now;
  struct tm *tm;
  gettimeofday(&now, NULL);
  tm = localtime(&now.tv_sec);
  char timebuf[32], usecbuf[7];
  strftime(timebuf, 32, "%H:%M:%S", tm);
  strcat(timebuf, ".");
  sprintf(usecbuf, "%d", (uint32_t) now.tv_usec);
  strcat(timebuf, usecbuf);
  if(verbose){
    fprintf(stderr, "%s Stream event %d\n", timebuf, event);
  }
  switch (event) {
    case STREAM_NETWORK_RECOVERED:
      if(verbose){
        fprintf(stderr, "Handling STREAM_NETWORK_RECOVERED callback\n");
      }
      list_add(data->streamlist, &streamid);
      break;
    case STREAM_OPENED:
      if(verbose){
        fprintf(stderr, "Handling STREAM_OPENED callback new stream %u\n", streamid);
      }
      list_add(data->streamlist, &streamid);
      tcpls_conn_t *conn;
      for (int i = 0; i < data->tcpls_conns->size; i++){
        /* code */
        conn = list_get(data->tcpls_conns, i);
        if (conn->tcpls == tcpls && conn->transportid == transportid) {
          conn->streamid = streamid;
          if(verbose){
            fprintf(stderr, "Stream id of connection %d is now %u\n", transportid, streamid);
          }
          break;
        } 
      }
      
      break;
    case STREAM_NETWORK_FAILURE:
      if(verbose){
        fprintf(stderr, "Handling STREAM_NETWORK_FAILURE callback, removing stream %u\n", streamid);
      }
      list_remove(data->streamlist, &streamid);
      break;
    case STREAM_CLOSED: ;
      if(verbose){
       fprintf(stderr, "Handling STREAM_CLOSED callback, removing stream %u\n", streamid);
      }
      list_remove(data->streamlist, &streamid);
      break;
    default: break;
  }
  return 0;
}

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

static int start_tunnel(tcpls_t *tcpls,internal_data_t *data, tcpls_buffer_t *recvbuf){
  struct sockaddr_in6 *peer_addr = data->peer_addr;
  uint8_t buf[22];
  buf[0] = TCP_CONNECT;
  buf[1] = 18;
  in_port_t * port = (in_port_t *) (buf + 2);
  *port = peer_addr->sin6_port;
  struct in6_addr *addr = (struct in6_addr *) (buf + 4);
  *addr = peer_addr->sin6_addr;
  buf[20] = END;
  buf[21] = 0;

  int ret;
  streamid_t *stream = NULL;
  for (size_t i = 0; i < data->streamlist->size; i++){
    stream = list_get(data->streamlist, i);
  }
  if(!stream){
    fd_set readset, writeset;
    int maxfd = 0;
    struct timeval timeout;
    memset(&timeout, 0, sizeof(struct timeval));
    tcpls_conn_t *conn;
    timeout.tv_sec = 100;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    for (int i = 0; i < data->tcpls_conns->size; i++) {
        conn = list_get(data->tcpls_conns, i);
        FD_SET(conn->socket , &readset);
        if (maxfd < conn->socket)
          maxfd = conn->socket;
    }
    select(maxfd+1, &readset, &writeset, NULL, &timeout);
    for(int i = 0 ; i < data->tcpls_conns->size ; i++){
        conn = list_get(data->tcpls_conns, i);
        if(FD_ISSET(conn->socket, &readset) && conn->state > CLOSED ){
            ret = handle_tcpls_read(conn->tcpls, conn->socket, recvbuf, data->streamlist, data->tcpls_conns);
        }
    }
    return -1;
  }

  if(verbose){
    fprintf(stderr, "opening tunnel\n");
  }

  while((ret = tcpls_send(tcpls->tls, *stream, buf, 22)) == TCPLS_CON_LIMIT_REACHED){
  }
  if(ret != 0) {
    fprintf(stderr, "tcpls_send returned %d for sending on streamid %u\n",
        ret, *stream);
    return -1;
  }


  fd_set readset, writeset;
  int maxfd = 0;
  struct timeval timeout;
  memset(&timeout, 0, sizeof(struct timeval));
  tcpls_conn_t *conn;
  timeout.tv_sec = 100;
  FD_ZERO(&readset);
  FD_ZERO(&writeset);
  for (int i = 0; i < data->tcpls_conns->size; i++) {
      conn = list_get(data->tcpls_conns, i);
      FD_SET(conn->socket , &readset);
      if (maxfd < conn->socket)
        maxfd = conn->socket;
  }
  select(maxfd+1, &readset, &writeset, NULL, &timeout);
  for(int i = 0 ; i < data->tcpls_conns->size ; i++){
    conn = list_get(data->tcpls_conns, i);
    if(FD_ISSET(conn->socket, &readset) && conn->state > CLOSED ){
        ret = handle_tcpls_read(conn->tcpls, conn->socket, recvbuf, data->streamlist, data->tcpls_conns);
        ptls_buffer_t *buf = tcpls_get_stream_buffer(recvbuf, conn->streamid);
        if(buf->off < 2){
          buf->off = 0;
          return -1;
        }
        tunnel_message_type type = buf->base[0];
        if(type != TCP_CONNECT_OK){
          buf->off = 0;
          return -1;
        }
        buf->off = 0;
        if(verbose){
          fprintf(stderr, "TCP tunnel opened %d\n", verbose);
        }
        return 0;
    }
  }
  return -1;
}

static int handle_latency_test(tcpls_t * tcpls, internal_data_t *data, tcpls_buffer_t * recvbuf){
  fd_set readset, writeset;
  int maxfd = 0;
  struct timeval timeout;
  memset(&timeout, 0, sizeof(struct timeval));
  tcpls_conn_t *conn;
  timeout.tv_sec = 100;
  while(1){
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    for (int i = 0; i < data->tcpls_conns->size; i++) {
        conn = list_get(data->tcpls_conns, i);
        FD_SET(conn->socket , &readset);
        if (maxfd < conn->socket)
          maxfd = conn->socket;
    }
    select(maxfd+1, &readset, &writeset, NULL, &timeout);
    for(int i = 0 ; i < data->tcpls_conns->size ; i++){
      conn = list_get(data->tcpls_conns, i);
      if(FD_ISSET(conn->socket, &readset) && conn->state > CLOSED ){
          int ret = handle_tcpls_read(conn->tcpls, conn->socket, recvbuf, data->streamlist, data->tcpls_conns);
          if(ret < 0){
            fprintf(stderr, "tcpls read return %d\n", ret);
          }
          ptls_buffer_t *buf = tcpls_get_stream_buffer(recvbuf, conn->streamid);
          if(buf->off > 0){
            struct timeval now;
            gettimeofday(&now, NULL);
            time_t sec = now.tv_sec - data->test_start_timer.tv_sec;
            suseconds_t usec = now.tv_usec - data->test_start_timer.tv_usec;
            if(usec < 0){
              usec += 1000000;
              sec -= 1;
            }
            printf("latency : %ld.%06ld\n", sec,usec);
            buf->off = 0;
            return 0;
          }
      }
    }
  }
}

static int handle_throughput_test(tcpls_t * tcpls, internal_data_t *data, tcpls_buffer_t * recvbuf){
  fd_set readset, writeset;
  int maxfd = 0;
  struct timeval timeout;
  memset(&timeout, 0, sizeof(struct timeval));
  tcpls_conn_t *conn;
  timeout.tv_sec = 100;
  long total_sent = 0;
  int ret;
  while(1){
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    for (int i = 0; i < data->tcpls_conns->size; i++) {
        conn = list_get(data->tcpls_conns, i);
        FD_SET(conn->socket , &readset);
        FD_SET(conn->socket , &writeset);
        if (maxfd < conn->socket)
          maxfd = conn->socket;
    }
    select(maxfd+1, &readset, &writeset, NULL, &timeout);
    for(int i = 0 ; i < data->tcpls_conns->size ; i++){
      conn = list_get(data->tcpls_conns, i);
      if(FD_ISSET(conn->socket, &readset) && conn->state > CLOSED ){
          ret = handle_tcpls_read(conn->tcpls, conn->socket, recvbuf, data->streamlist, data->tcpls_conns);
          ptls_buffer_t *buf = tcpls_get_stream_buffer(recvbuf, conn->streamid);
          if(buf->off > 0){
            buf->off = 0; // ignore received data
          }
      }      
      if(FD_ISSET(conn->socket, &writeset) && conn->state > CLOSED){
        static const size_t block_size = 4 * PTLS_MAX_ENCRYPTED_RECORD_SIZE;
        uint8_t buf[block_size];
        conn = list_get(data->tcpls_conns, 0);
        size_t to_send = block_size;
        while((ret = tcpls_send(tcpls->tls, conn->streamid, buf, to_send)) == TCPLS_CON_LIMIT_REACHED){
        }
        if(ret != 0){
          fprintf(stderr, "tcpls_send returned %d for sending on streamid %u\n",
              ret, conn->streamid);
          return -1;
        }
        total_sent += to_send;
      }
    }
    if(total_sent >= 10000000000){
      return 0;
    }
  }
}


static int handle_tunnel_transfer(tcpls_t *tcpls,internal_data_t *data,int io_fd, int fast, performance_test test){
    int ret;
    tcpls_buffer_t *recvbuf = tcpls_stream_buffers_new(tcpls, 2);
    if(handle_tcpls_read(tcpls, 0, recvbuf, data->streamlist, data->tcpls_conns) < 0){
        tcpls_buffer_free(tcpls, recvbuf);
        return -1;
    }
    if(verbose){
      fprintf(stderr, "Hanshake done\n");
    }

  do{
   ret = start_tunnel(tcpls, data, recvbuf);
  } while(ret);

  fd_set readset, writeset;
  int maxfd = 0;
  struct timeval timeout;
  memset(&timeout, 0, sizeof(struct timeval));
  tcpls_conn_t *conn;
  timeout.tv_sec = 100;

  switch (test){
  case T_THROUGHPUT:
    return handle_throughput_test(tcpls, data, recvbuf);
    break;
  case T_LATENCY:
    return handle_latency_test(tcpls, data, recvbuf);
    break;
  default:
    break;
  }

  while(1){

    //cleanup
    for (int i = 0; i < data->tcpls_conns->size; i++) {
        conn = list_get(data->tcpls_conns, i);
        if(conn->state == CLOSED){
          printf("Removing connection %d", conn->transportid);
          list_remove(data->tcpls_conns, conn);
        }
    }

    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    for (int i = 0; i < data->tcpls_conns->size; i++) {
        conn = list_get(data->tcpls_conns, i);
        FD_SET(conn->socket , &readset);
        FD_SET(conn->socket , &writeset);
        if (maxfd < conn->socket)
          maxfd = conn->socket;
    }
    FD_SET(io_fd, &readset);
    
    select(maxfd+1, &readset, &writeset, NULL, &timeout);
    for(int i = 0 ; i < data->tcpls_conns->size ; i++){
      conn = list_get(data->tcpls_conns, i);
      if(FD_ISSET(conn->socket, &readset) && conn->state > CLOSED ){
          ret = handle_tcpls_read(conn->tcpls, conn->socket, recvbuf, data->streamlist, data->tcpls_conns);
          ptls_buffer_t *buf = tcpls_get_stream_buffer(recvbuf, conn->streamid);
          buf->off = 0;
      }
      if(FD_ISSET(conn->socket, &writeset) && conn->state > CLOSED){
        static const size_t block_size = 4 * PTLS_MAX_ENCRYPTED_RECORD_SIZE;
        uint8_t buf[block_size];
        conn = list_get(data->tcpls_conns, 0);
        size_t to_send = block_size;
        if(!fast){
          to_send = read(io_fd, buf, block_size);
        }
        if(to_send < 0){
          fprintf(stderr, "Error reading file\n");
          return -1;
        }
        else if(to_send == 0){
          if(verbose){
            fprintf(stderr, "Transfer complete \n");
          }
          tcpls_stream_close(conn->tcpls->tls, conn->streamid, 1);
          return 0;
        } else{
          while((ret = tcpls_send(tcpls->tls, conn->streamid, buf, to_send)) == TCPLS_CON_LIMIT_REACHED){
          }
          if(ret != 0){
            fprintf(stderr, "tcpls_send returned %d for sending on streamid %u\n",
                ret, conn->streamid);
            close(io_fd);
            return -1;
          }
        }
      }
    }

    
  }


  return ret;
}


static int start_client(struct sockaddr_storage *sockaddrs, int nb_addrs, ptls_context_t *ctx,ptls_handshake_properties_t *hsprop, internal_data_t *data,const char *server_name ,const char *input_file, int fast, performance_test test){
    hsprop->client.esni_keys = resolve_esni_keys(server_name);
    data->tcpls_conns = new_list(sizeof(tcpls_conn_t), 2);
    data->streamlist = new_list(sizeof(streamid_t), 2);

    //Call backs
    ctx->stream_event_cb = &handle_client_stream_event;
    ctx->connection_event_cb = &handle_connection_event;
    ctx->cb_data = data;

    tcpls_t *tcpls = tcpls_new(ctx, 0);
    tcpls_add_ips(tcpls, NULL, (struct sockaddr_storage *) sockaddrs, 0, nb_addrs);
    ctx->output_decrypted_tcpls_data = 0;
    signal(SIGPIPE, sig_handler);
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(test != T_NOTEST){
      gettimeofday(&data->test_start_timer, NULL);
    }

    int err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout);
    if(err){
        fprintf(stderr, "tcpls_connect failed with err %d\n", err);
        return 1;
    }
    tcpls->enable_multipath = 1;

    int io_fd = 0;
    if(input_file){
      io_fd = open(input_file, O_RDONLY);
      if(io_fd < 0){
        fprintf(stderr, "Failed to open file %s\n", input_file);
        return -1;
      }
    } 

    handle_tunnel_transfer(tcpls, data, io_fd, fast, test);
    free_data(data);
    
    return 0;

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

    int ch, fast = 0;
    performance_test test = T_NOTEST;
    const char *proxy_host, *proxy_port,*tcp_host, *tcp_port, *input_file = NULL;

    internal_data_t data = {NULL};

    data.proxy_addrsV6 = new_list(40,2);
    data.proxy_addrs = new_list(16,2);

    while((ch = getopt(argc, argv, "vt:fi:p:P:")) != -1){
        switch (ch){
        case 'f':{
            fast = 1;
            break;
        }
        case 'i':{
          input_file = optarg;
          break;
        }
        case 'p':{
            char addr[16];
            int addrlen = strlen(optarg);
            if(addrlen > 15){
                fprintf(stderr, "Not a valid addr: %s\n", optarg);
                exit(1);
            }
            memcpy(addr, optarg, addrlen);
            addr[addrlen] = '\0';
            list_add(data.proxy_addrs,addr);
            break;
        }
        case 'P':{
            char addr[40];
            int addrlen = strlen(optarg);
            if(addrlen > 39){
                fprintf(stderr, "Not a valid addr: %s\n", optarg);
                exit(1);
            }
            memcpy(addr, optarg, addrlen);
            addr[addrlen] = '\0';
            list_add(data.proxy_addrsV6,addr);
            break;        
        }
        case 't':{
          if(strcasecmp(optarg, "throughput") == 0)
            test = T_THROUGHPUT;
          else if(strcasecmp(optarg, "latency") == 0)
            test = T_LATENCY;
          else{
            fprintf(stderr, "Unknown test: %s\n", optarg);
          }
          break;
        }
        case 'v':{
          verbose = 1;
          break;
        }
        default:
            break;
        }
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
    if (argc != 4) {
        fprintf(stderr, "missing host and port\n");
        return 1;
    }
    proxy_host = (--argc, *argv++);
    proxy_port = (--argc, *argv++);
    tcp_host = (--argc, *argv++);
    tcp_port = (--argc, *argv++);

    int idx = 0;
    int nbr_addrs = data.proxy_addrs->size + data.proxy_addrsV6->size + 1;
    struct sockaddr_storage sockaddrs[nbr_addrs];
    socklen_t sa_len;
    char *addr;
    for (int i = 0; i < data.proxy_addrs->size; i++) {
        addr = list_get(data.proxy_addrs, i);
        if (resolve_address((struct sockaddr *)&sockaddrs[i], &sa_len, addr, proxy_port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0){
            fprintf(stderr, "Failed to resolve addr: %s\n", addr);
            exit(1);
        }
    }
    idx += data.proxy_addrs->size;
    for (int i = 0; i < data.proxy_addrsV6->size; i++) {
        addr = list_get(data.proxy_addrsV6, i);
        if (resolve_address((struct sockaddr *)&sockaddrs[i+idx], &sa_len, addr, proxy_port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0){
            fprintf(stderr, "Failed to resolve addr: %s\n", addr);
            exit(1);
        }
    }
    idx += data.proxy_addrsV6->size;
    if (resolve_address((struct sockaddr*)&sockaddrs[idx], &sa_len, proxy_host, proxy_port,0, SOCK_STREAM, IPPROTO_TCP) != 0){
        fprintf(stderr, "Failed to resolve addr: %s\n", proxy_host);        
        exit(1);
    }

    struct sockaddr_storage tcp_sockaddr;
    if (resolve_address((struct sockaddr*)&tcp_sockaddr, &sa_len, tcp_host, tcp_port, 0 , SOCK_STREAM, IPPROTO_TCP) != 0){
        fprintf(stderr, "Failed to resolve addr: %s\n", proxy_host);        
        exit(1);
    }
    if(tcp_sockaddr.ss_family == AF_INET){
        //Convert
        struct sockaddr_in *v4 = (struct sockaddr_in *) &tcp_sockaddr;
        struct sockaddr_in6 v6;
        memset(&v6, 0, sizeof(struct sockaddr_in6));
        v6.sin6_family = AF_INET6;
        v6.sin6_port = v4->sin_port;
        uint8_t *addr = v6.sin6_addr.s6_addr;
        memset(addr+10, 0xff, 2);
        memcpy(addr+12, &v4->sin_addr, sizeof(struct in_addr));
        data.peer_addr = malloc(sizeof(struct sockaddr_in6));
        memcpy(data.peer_addr, &v6, sizeof(struct sockaddr_in6));
    } else{
        data.peer_addr = (struct sockaddr_in6 *) &tcp_sockaddr;

    }
 
    char myIPString[40];
    inet_ntop(AF_INET6, &data.peer_addr->sin6_addr, myIPString, sizeof(myIPString));
    
    return start_client(sockaddrs, nbr_addrs, &ctx, &hsprop, &data, proxy_host ,input_file, fast, test);
}