#######server side:

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>  
#include "dlfcn.h"

#define CERTSERVER "serverCert.cer"
#define KEYSERVER "serverKey.pem"

#define CHK_ERR(err, s) if((err) == -1) { perror(s); return -1; }
#define CHK_RV(rv, s) if((rv) != 1) { printf("%s error\n", s); return -1; }
#define CHK_NULL(x, s) if((x) == NULL) { printf("%s error\n", s); return -1; }
#define CHK_SSL(err, s) if((err) == -1) { ERR_print_errors_fp(stderr);  return -1;}

int main()
{
	int rv, err;
	SSL_CTX *ctx = NULL;
	SSL_METHOD *meth = NULL;
	int listen_sd;
	int accept_sd;
	struct sockaddr_in socketAddrServer;
	struct sockaddr_in socketAddrClient;
	int socketAddrClientLen;
	SSL *ssl = NULL;
	char buf[4096];

	rv = SSL_library_init();
	CHK_RV(rv, "SSL_library_init");

	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	CHK_NULL(ctx, "SSL_CTX_new");

	rv = SSL_CTX_use_certificate_file(ctx, CERTSERVER, SSL_FILETYPE_PEM);
	CHK_RV(rv, "SSL_CTX_use_certicificate_file");

	rv = SSL_CTX_use_PrivateKey_file(ctx, KEYSERVER, SSL_FILETYPE_PEM);
	CHK_RV(rv, "SSL_CTX_use_PrivateKey_file");
	
	rv = SSL_CTX_check_private_key(ctx);
	CHK_RV(rv, "SSL_CTX_check_private_key");
	
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");
	memset(&socketAddrServer, 0, sizeof(socketAddrServer));
	socketAddrServer.sin_family = AF_INET;
	socketAddrServer.sin_port = htons(8443);
	socketAddrServer.sin_addr.s_addr = INADDR_ANY;

	err = bind(listen_sd, (struct sockaddr *)&socketAddrServer, sizeof(socketAddrServer));
	CHK_ERR(err, "bind");
	err = listen(listen_sd, 5);
	CHK_ERR(err, "listen");

	socketAddrClientLen = sizeof(socketAddrClient);
	accept_sd = accept(listen_sd, (struct sockaddr *)&socketAddrClient, &socketAddrClientLen);
	CHK_ERR(accept_sd, "accept");
	close(listen_sd);
	printf("Connect to %lx, port %x\n", socketAddrClient.sin_addr.s_addr, socketAddrClient.sin_port);

	ssl = SSL_new(ctx);
	CHK_NULL(ssl, "SSL_new");
	rv = SSL_set_fd(ssl, accept_sd);
	CHK_RV(rv, "SSL_set_fd");
	rv = SSL_accept(ssl);
	CHK_RV(rv, "SSL_accpet");

	rv = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(rv, "SSL_read");
	buf[rv] = '\0';
	printf("Got %d chars :%s\n", rv, buf);
	rv = SSL_write(ssl, "I accept your request", strlen("I accept your request"));
	CHK_SSL(rv, "SSL_write");

	close(accept_sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

#######Client side:
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>  
#include "dlfcn.h"

#define CHK_ERR(err, s) if((err) == -1) { perror(s); return -1; }
#define CHK_RV(rv, s) if((rv) != 1) { printf("%s error\n", s); return -1; }
#define CHK_NULL(x, s) if((x) == NULL) { printf("%s error\n", s); return -1; }
#define CHK_SSL(err, s) if((err) == -1) { ERR_print_errors_fp(stderr);  return -1;}

int main()
{
	int rv;
	int err;
	int listen_sd;
	struct sockaddr_in socketAddrClient;
	SSL_METHOD *meth = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	char buf[4096];

	rv = SSL_library_init();
	CHK_RV(rv, "SSL_library_init");

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	CHK_NULL(ctx, "SSL_CTX_new");

	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");
	memset(&socketAddrClient, 0, sizeof(socketAddrClient));
	socketAddrClient.sin_family = AF_INET;
	socketAddrClient.sin_port = htons(8443);
	socketAddrClient.sin_addr.s_addr = inet_addr("127.0.0.1");

	err = connect(listen_sd, (struct sockaddr *)&socketAddrClient, sizeof(socketAddrClient));
	CHK_ERR(err, "connect");
	ssl = SSL_new(ctx);
	CHK_NULL(ssl, "SSL_new");
	rv = SSL_set_fd(ssl, listen_sd);
	CHK_RV(rv, "SSL_set_fd");
	rv = SSL_connect(ssl);
	CHK_RV(rv, "SSL_connect");

	rv = SSL_write(ssl, "Hello, I am the client", strlen("Hello, I am the client"));
	CHK_SSL(rv, "SSL_write");
	rv = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(rv, "SSL_read");
	buf[rv] = '\0';
	printf("Got %d chars :%s\n", rv, buf);

	SSL_shutdown(ssl);
	close(listen_sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

####可用gcc编译后做测试
