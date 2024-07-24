#include <stdio.h>
#include <sys/uio.h>
#include <string.h>
#include <assert.h>
#include <ssl.h>

#ifndef KITSERV_TLS_H
#define KITSERV_TLS_H

SSL_CTX* kitserv_tls_init();
ssize_t SSL_writev_ex(SSL* ssl, const struct iovec *vector, int count);
ssize_t SSL_sendfile(SSL* ssl, int in_fd, off_t* offset, size_t count);

#endif
