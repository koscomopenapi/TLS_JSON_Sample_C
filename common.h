#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <jansson.h>
#include "reentrant.h"
#include "message.h"

#ifndef WIN32
#include <pthread.h>
#define THREAD_CC
#define THREAD_TYPE                    pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, \
                                                      (entry), (arg))
#else
#include <windows.h>
#define THREAD_CC                      __cdecl
#define THREAD_TYPE                    DWORD
#define THREAD_CREATE(tid, entry, arg) do { _beginthread((entry), 0, (arg));\
                                            (tid) = GetCurrentThreadId();   \
                                       } while (0)
#endif
#define BUFSIZZ 1024

#define PORT            "16001"
#define SERVER          "localhost"
#define CLIENT          "localhost"

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char *msg);

void init_OpenSSL(void);

int verify_callback(int ok, X509_STORE_CTX *store);

long post_connection_check(SSL *ssl, char *host);

void seed_prng(void);

#endif /* COMMON_H */
