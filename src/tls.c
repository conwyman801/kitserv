#include "tls.h"

SSL_CTX* kitserv_tls_init() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        perror("ssl context");
        exit(1);
    }

    // Enforce TLS version >= 1.2
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx);
        printf("Error: Deprecated TLS version! (< 1.2)");
        exit(0);
    }

    // Options for security
    long opts = SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE;
    SSL_CTX_set_options(ctx, opts);

    // Load certificate + private key
    // TODO make file names configurable
    // TODO config file? (literally spring)
    if (SSL_CTX_use_certificate_chain_file(ctx, "bin/chain.pem") <= 0) {
        SSL_CTX_free(ctx);
        perror("ssl certificate");
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "bin/pkey.pem", SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        perror("ssl private key");
        exit(1);
    }

    // TODO enable caching

    // Not doing mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

// https://fossies.org/dox/glibc-2.39/sysdeps_2posix_2writev_8c_source.html
ssize_t SSL_writev(SSL* ssl, const struct iovec *vector, int count) {
    ssize_t buf_sz = 0;
    for (int i = 0; i < count; i++) {
        buf_sz += vector[i].iov_len;
    }

    // TODO i know this is slow
    char* write_buf = (char*) calloc(buf_sz, sizeof(char));
    ssize_t ptr = 0;
    for (int i = 0; i < count; i++) {
        memcpy(write_buf + ptr, vector[i].iov_base, vector[i].iov_len);
        ptr += vector[i].iov_len;
    }

    int rc = SSL_write(ssl, write_buf, buf_sz);
    free(write_buf);
    
    return rc;
}

// copied sendfile_emulation function from http.c
ssize_t SSL_sendfile(SSL* ssl, int in_fd, off_t* offset, size_t count)
{
    const int SFE_BUFSZ = 4096;  // small, but (A) stack allocated and (B) need to re-read if EAGAIN is hit on send
    char buf[SFE_BUFSZ];
    ssize_t remaining, read, sent;

    // sendfile only transfers at most 0x7ffff000 bytes (which helps us fit in the ssize_t return type)
    assert(0x7ffff000 <= (size_t)-1);
    if (count > 0x7ffff000) {
        count = 0x7ffff000;
    }
    remaining = count;

    do {
        read = pread(in_fd, buf, SFE_BUFSZ < remaining ? SFE_BUFSZ : remaining, *offset);
        if (read < 0) {
            goto err;
        }

        sent = 0;
        do {
            // sent = write(out_fd, buf, read);
            sent = SSL_write(ssl, buf, read);
            // TODO is 0 success or failure?
            // right now counting it as failure
            if (sent <= 0) {
                goto err;
            }
        } while (sent < read);

        remaining -= sent;
        *offset += sent;
    } while (remaining > 0);

    return count - remaining;

err:
    if (count - remaining > 0) {
        return count - remaining;
    }
    return -1;
}
