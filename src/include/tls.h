#include <stdio.h>
#include <sys/uio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <ssl.h>

#ifndef KITSERV_TLS_H
#define KITSERV_TLS_H

int parse_to_value(char* buf);
SSL_CTX* ssl_ctx_from_config();

SSL_CTX* kitserv_tls_init();
SSL_CTX* kitserv_tls_init_config(char* path);
ssize_t SSL_writev(SSL* ssl, const struct iovec *vector, int count);
ssize_t SSL_sendfile(SSL* ssl, int in_fd, off_t* offset, size_t count);

struct kitserv_tls_config_line {
    char* label;
    char* default_value;
    char* new_value;
};

#define KITSERV_TLS_CFG_ITEMS 2
#define KITSERV_CFG_BUFSZ 1024

extern struct kitserv_tls_config_line kitserv_tls_config[KITSERV_TLS_CFG_ITEMS];

#endif
