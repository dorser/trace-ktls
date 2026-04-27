/*
 * ktls_client.c — Minimal HTTPS client that enables kTLS.
 *
 * 1. Connects to httpbin.org:443 over TCP.
 * 2. Performs a TLS 1.3 handshake with OpenSSL (kTLS enabled).
 * 3. Sends a plaintext HTTP GET via SSL_write() — the kernel
 *    encrypts it in the TLS ULP, where our eBPF gadget can see it.
 * 4. Reads and prints the response.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define HOST "httpbin.org"
#define PORT "443"

static const char REQUEST[] =
    "GET /get HTTP/1.1\r\n"
    "Host: " HOST "\r\n"
    "User-Agent: ktls-demo/1.0\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n";

static void die_ssl(const char *msg)
{
    fprintf(stderr, "%s: ", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res;

    int err = getaddrinfo(host, port, &hints, &res);
    if (err) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(1);
    }

    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        perror("connect");
        exit(1);
    }
    return fd;
}

static void show_ktls_status(SSL *ssl)
{
    BIO *wbio = SSL_get_wbio(ssl);
    BIO *rbio = SSL_get_rbio(ssl);

    int tx = wbio ? BIO_get_ktls_send(wbio) : 0;
    int rx = rbio ? BIO_get_ktls_recv(rbio) : 0;

    printf("┌─────────────────────────────────┐\n");
    printf("│  kTLS TX: %-22s│\n", tx ? "✓ ACTIVE" : "✗ inactive");
    printf("│  kTLS RX: %-22s│\n", rx ? "✓ ACTIVE" : "✗ inactive");
    printf("│  Cipher:  %-22s│\n", SSL_get_cipher_name(ssl));
    printf("│  Version: %-22s│\n", SSL_get_version(ssl));
    printf("└─────────────────────────────────┘\n");

    if (!tx)
        fprintf(stderr,
                "\n⚠  kTLS TX not active — the eBPF gadget won't see "
                "plaintext.\n"
                "   Possible causes: cipher not supported by kernel kTLS, "
                "or OpenSSL built without KTLS.\n\n");
}

int main(void)
{
    /* ── OpenSSL init ─────────────────────────────────── */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        die_ssl("SSL_CTX_new");

    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

    /* Prefer ciphers that the kernel TLS ULP supports. */
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);

    /* ── TCP connect ──────────────────────────────────── */
    printf("Connecting to %s:%s …\n", HOST, PORT);
    int fd = tcp_connect(HOST, PORT);
    printf("TCP connected (fd=%d)\n", fd);

    /* ── TLS handshake ────────────────────────────────── */
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
        die_ssl("SSL_new");

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, HOST);
    SSL_set1_host(ssl, HOST);

    if (SSL_connect(ssl) <= 0)
        die_ssl("SSL_connect");

    printf("TLS handshake complete\n");
    show_ktls_status(ssl);

    /* ── Send HTTP request (kTLS encrypts in-kernel) ─── */
    printf("Sending request:\n%s", REQUEST);
    if (SSL_write(ssl, REQUEST, sizeof(REQUEST) - 1) <= 0)
        die_ssl("SSL_write");

    /* ── Read response ────────────────────────────────── */
    printf("─── Response ────────────────────────────────\n");
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }
    printf("\n─────────────────────────────────────────────\n");

    /* ── Cleanup ──────────────────────────────────────── */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);

    return 0;
}
