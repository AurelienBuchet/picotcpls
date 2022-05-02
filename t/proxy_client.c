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

static int start_client(){

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
    const char *host, *port, *input_file = NULL;
    while((ch = getopt(argc, argv, "f:p:P:")) != -1){
        switch (ch){
        case 'f':{
            input_file = optarg;
            break;
        }
        case 'p':{
            /* add v4 addr*/
            break;
        }
        case 'P':{
            /* add v6 addr*/
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
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        return 1;
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    return start_client();
}