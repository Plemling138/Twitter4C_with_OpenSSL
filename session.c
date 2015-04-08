/* session.c - SSL connection for api.twitter.com
 * (C)2013-15 Plemling138
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "twilib.h"
#include "session.h"

#define SHOW_RESPONSE 0

int sock = 0;

int SSL_send_and_recv(char *hostname, char *send_buf, char *recv_buf)
{
  SSL* ssl;
  SSL_CTX* ctx;
  int ret = 0, read_size = 0;

  struct sockaddr_in addr;
  struct hostent *host = 0;

  //DNS Resolve
  if((host = gethostbyname(hostname)) == NULL) {
    printf("Failed to resolve host\n");
    return -1;
  }

  //Set port number
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = *((unsigned long *)host->h_addr_list[0]);
  addr.sin_port = htons(443);

  //Create socket
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  //Connect
  if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    printf("Cannot connect to Twitter server.\n");
    return -1;
  }

  //Initialize SSL
  SSL_load_error_strings();
  SSL_library_init();
  
  //Set CTX
  ctx = SSL_CTX_new(TLSv1_2_client_method());
  if(ctx == NULL) {
    return -2;
  }

  //Set SSL Connection
  ssl = NULL;
  ssl = SSL_new(ctx);
  if(ssl == NULL) {
    return -3;
  }
  
  //Set Socket and SSL
  ret = SSL_set_fd(ssl, sock);
  if(ret == 0) {
    return -4;
  }

  //Connect SSL
  ret = SSL_connect(ssl);
  if(ret != 1) {
    return -5;
  }

  //Send Request
  if(SSL_write(ssl, (void *)send_buf, strlen((void *)send_buf)) == -1) {
    return -6;
  }

  //Get Response
  while((read_size = SSL_read(ssl, recv_buf, BUF_SIZE-1)) > 0) {
	recv_buf[read_size] = '\0';
#if SHOW_RESPONSE
    printf(recv_buf);
#endif
  }

#if SHOW_RESPONSE
	printf("\n");
#endif

  //Close SSL Session
  ret = SSL_shutdown(ssl);
  if(ret != 0) {
    return -7;
  }
  close(sock);
  
  return 0;
}
