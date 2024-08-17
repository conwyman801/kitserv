#include "tls.h"

struct kitserv_tls_config_line kitserv_tls_config[KITSERV_TLS_CFG_ITEMS] = {
    {"server_cert_pem", "bin/chain.pem", NULL},
    {"server_private_key", "bin/pkey.pem", NULL}
};

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

int parse_to_value(char* buf) {
    int ptr = 0;
    while (ptr < KITSERV_CFG_BUFSZ && buf[ptr] != 0 && buf[ptr] != '=') {
        ptr++;
    }
    
    // didn't find an =
    if (buf[ptr] == 0) {
        return -1;
    }

    ptr++;
    while (ptr < KITSERV_CFG_BUFSZ && buf[ptr] != 0 && isspace(buf[ptr])) {
        ptr++;
    }
    return ptr;
}

SSL_CTX* ssl_ctx_from_config() {
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
    char* chain_cert_path = kitserv_tls_config[0].new_value == NULL ? kitserv_tls_config[0].default_value : kitserv_tls_config[0].new_value;
    printf("TLS: loading %s %s %s\n", kitserv_tls_config[0].new_value == NULL ? "default" : "configured", kitserv_tls_config[0].label, chain_cert_path);
    if (SSL_CTX_use_certificate_chain_file(ctx, chain_cert_path) <= 0) {
        SSL_CTX_free(ctx);
        perror("ssl certificate");
        exit(1);
    }
    if (kitserv_tls_config[0].new_value != NULL) {
        free(kitserv_tls_config[0].new_value);
    }

    char* private_key_path = kitserv_tls_config[1].new_value == NULL ? kitserv_tls_config[1].default_value : kitserv_tls_config[1].new_value;
    printf("TLS: loading %s %s %s\n", kitserv_tls_config[1].new_value == NULL ? "default" : "configured", kitserv_tls_config[1].label, private_key_path);
    if (SSL_CTX_use_PrivateKey_file(ctx, private_key_path, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        perror("ssl private key");
        exit(1);
    }
    if (kitserv_tls_config[1].new_value != NULL) {
        free(kitserv_tls_config[1].new_value);
    }

    // TODO SSL enable/disable
    // TODO enable caching

    // TODO mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

SSL_CTX* kitserv_tls_init_config(char* path) {
    // TODO default path
    // TODO what if we don't have a file?
    // open file
    printf("TLS: loading config from %s\n", path);
    FILE* file = fopen(path, "r");
    if (file == NULL) {
        perror("Unable to open SSL config file!\n");
        exit(1);
    }

    // for line in file:
    char* buf = (char*) calloc(KITSERV_CFG_BUFSZ, sizeof(char));
    while (fgets(buf, KITSERV_CFG_BUFSZ, file)) {
        // skip comments
        if (buf[0] == '#') {
            continue;
        }

        int config_item_row = -1;

        //  try to match to config item
        for (int i = 0; i < KITSERV_TLS_CFG_ITEMS; i++) {
            if (strstr(buf, kitserv_tls_config[i].label) == buf) {
                config_item_row = i;
                break;
            }
        }

        // we didn't find a config item
        if (config_item_row == -1) {
            continue;
        }

        // set last char to not be newline
        buf[strlen(buf) - 1] = 0;
        
        int ptr = parse_to_value(buf);
        
        // skip invalid lines TODO log
        if (ptr == -1) {
            continue;
        }

        char* value = buf + ptr;

        char* stored_value = (char*) calloc(strlen(value) + 1, sizeof(char));
        if (stored_value == NULL) {
            perror("calloc");
            exit(1);
        }
        if (memcpy(stored_value, value, strlen(value)) == NULL) {
            perror("memcpy");
            exit(1);
        }

        //  set config item
        kitserv_tls_config[config_item_row].new_value = stored_value;

    }
    free(buf);
    fclose(file);

    // build SSL CTX from config items

    return ssl_ctx_from_config();
    
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
