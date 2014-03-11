/* twilib.c - Twitter Library
 * (C)2013-14 Plemling138
 */

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netdb.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/time.h>

#include "hmac.h"
#include "base64.h"
#include "urlenc.h"
#include "extract.h"
#include "twilib.h"
#include "session.h"

int Twitter_GetRequestToken(struct Twitter_consumer_token *c, struct Twitter_request_token *r)
{
  int i;

  char buf[BUF_SIZE] = {'\0'};

  char oauth_signature_key[60] = {'\0'};

  struct timeval tv;
  char tstamp[20] = {'\0'};

  char nonce_tmp[20] = {'\0'};
  char nonce[20] = {'\0'};
  char nonce_urlenc[20] = {'\0'};

  char auth_tmpmsg[200] = {'\0'};//Temporary message for HMAC-SHA1
  char auth_encmsg[250] = {'\0'};//Temporary message for HMAC-SHA1(URL-Encoded)
  char auth_postmsg[250] = {'\0'};

  char tmp_token[200] = {'\0'};
  char tmp_secret[200] = {'\0'};

  char postmsg[400] = {'\0'};//POST Header
  char reqheader[500] = {'\0'};//POST Header

  char hmacmsg[40] = {'\0'};
  char b64msg[40] = {'\0'};

  char b64urlenc[50] = {'\0'};

  //Signature Key
  sprintf(oauth_signature_key, "%s&", c->consumer_secret);

  //Get date, set as timestamp
  gettimeofday(&tv, NULL);
  sprintf(tstamp, "%ld", tv.tv_sec);

  sprintf(nonce_tmp, "%ld", tv.tv_usec);
  base64_encode(nonce_tmp, strlen(nonce_tmp), nonce, 128);
  URLEncode(nonce, nonce_urlenc);

  //Generate OAuth Post message
  sprintf(auth_tmpmsg, "%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp,  OAUTH_VER, OAUTH_VER_NUM);
  URLEncode(auth_tmpmsg, auth_encmsg);
  sprintf(auth_postmsg, "%s&%s&%s", MSG_POST, REQUEST_TOKEN_ENCODED_URL, auth_encmsg);

  //Generate OAuth Signature
  hmac_sha1(oauth_signature_key, strlen(oauth_signature_key), auth_postmsg, strlen(auth_postmsg), hmacmsg);

  //Count Singnature length
  //break null character After three consecutive
  i=0;
  while(i < (40 - 3)) {
    if(hmacmsg[i] == '\0' && hmacmsg[i+1] == '\0' && hmacmsg[i+2] == '\0') break;
    i++;
  }

  //Encode Signature text by BASE64, also URL Encode
  base64_encode(hmacmsg, i, b64msg, 128);
  URLEncode(b64msg, b64urlenc);

  //Generate POST Message
  sprintf(postmsg, "%s%s&%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce_urlenc, OAUTH_SIG, b64urlenc, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp, OAUTH_VER, OAUTH_VER_NUM);
  
  sprintf(reqheader, "POST %s %s\r\nHost: %s\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s\r\n\r\n", REQUEST_TOKEN_URL, HTTP_VER, HOSTNAME, CONTENT_TYPE, (int)strlen(postmsg), postmsg);

  //SSL Session
  SSL_send_and_recv((char *)HOSTNAME, reqheader, buf);

  //Extract OAuth token and secret from received data
  if(ExtractQuery(buf, "oauth_token=", tmp_token) < 0) return -8;
  if(ExtractQuery(buf, "oauth_token_secret=", tmp_secret) < 0) return -9;

  r->request_token = (char *)calloc((strlen(tmp_token))+1, sizeof(char));
  if(r->request_token == NULL) return -10;
  memcpy(r->request_token, tmp_token, strlen(tmp_token));

  r->request_secret = (char *)calloc((strlen(tmp_secret))+1, sizeof(char));
  if(r->request_secret == NULL) return -11;
  memcpy(r->request_secret, tmp_secret, strlen(tmp_secret));

  return 0;
}

int Twitter_GetAccessToken(struct Twitter_consumer_token *c, struct Twitter_request_token *r, struct Twitter_access_token *a)
{
  char buf[BUF_SIZE] = {'\0'};

  char oauth_signature_key[100] = {'\0'};

  struct timeval tv;
  char tstamp[20] = {'\0'};

  char nonce_tmp[20] = {'\0'};
  char nonce[20] = {'\0'};
  char nonce_urlenc[20] = {'\0'};

  char auth_tmpmsg[400] = {'\0'};//Temporary message for HMAC-SHA1
  char auth_encmsg[450] = {'\0'};//Temporary message for HMAC-SHA1(URL-Encoded)
  char auth_postmsg[450] = {'\0'};

  char tmp_token[200] = {'\0'};
  char tmp_secret[200] = {'\0'};

  char postmsg[400] = {'\0'};//POST Header
  char reqheader[500] = {'\0'};//POST Header

  char hmacmsg[40] = {'\0'};
  char b64msg[40] = {'\0'};

  char b64urlenc[50] = {'\0'};
  
  char tmp_usrid[20] = {0};
  char tmp_usrname[20] = {0};

  int i = 0;

  //Signature Key
  sprintf(oauth_signature_key, "%s&%s", c->consumer_secret, r->request_secret);

  //Get date, set as timestamp
  gettimeofday(&tv, NULL);
  sprintf(tstamp, "%ld", tv.tv_sec);

  sprintf(nonce_tmp, "%ld", tv.tv_usec);
  base64_encode(nonce_tmp, strlen(nonce_tmp), nonce, 128);
  URLEncode(nonce, nonce_urlenc);

  //Generate OAuth Post message
  sprintf(auth_tmpmsg, "%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp,  OAUTH_TOKEN, r->request_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, OAUTH_VER_NUM);
  URLEncode(auth_tmpmsg, auth_encmsg);
  sprintf(auth_postmsg, "%s&%s&%s", MSG_POST, ACCESS_TOKEN_ENCODED_URL, auth_encmsg);

  //Generate OAuth Signature
  hmac_sha1(oauth_signature_key, strlen(oauth_signature_key), auth_postmsg, strlen(auth_postmsg), hmacmsg);

  //Count Singnature length
  i=0;
  while(i < (40 - 3)) {
    if(hmacmsg[i] == 0 && hmacmsg[i+1] == 0 && hmacmsg[i+2] == 0) break;
    i++;
  }

  //Encode Signature text by BASE64, also URL Encode
  base64_encode(hmacmsg, i, b64msg, 128);
  URLEncode(b64msg, b64urlenc);

  //Generate POST Message
  sprintf(postmsg, "%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce_urlenc, OAUTH_SIG, b64urlenc, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp, OAUTH_TOKEN, r->request_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, OAUTH_VER_NUM);
  
  sprintf(reqheader, "POST %s %s\r\nHost: %s\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s\r\n\r\n", ACCESS_TOKEN_URL, HTTP_VER, HOSTNAME, CONTENT_TYPE, (int)strlen(postmsg), postmsg);

  //SSL Session
  SSL_send_and_recv((char *)HOSTNAME, reqheader, buf);

  //Extract OAuth token and secret from received data
  if(ExtractQuery(buf, "oauth_token=", tmp_token) < 0) return -8;
  if(ExtractQuery(buf, "oauth_token_secret=", tmp_secret) < 0) return -9;
  if(ExtractQuery(buf, "user_id=", tmp_usrid) < 0) return -10;
  if(ExtractQuery(buf, "screen_name=", tmp_usrname) < 0) return -11;

  a->access_token = (char *)calloc((strlen(tmp_token))+1, sizeof(char));
  if(a->access_token == NULL) return -12;
  memcpy(a->access_token, tmp_token, strlen(tmp_token));

  a->access_secret = (char *)calloc((strlen(tmp_secret))+1, sizeof(char));
  if(a->access_secret == NULL) return -13;
  memcpy(a->access_secret, tmp_secret, strlen(tmp_secret));

  a->user_id = (char *)calloc((strlen(tmp_usrid))+1, sizeof(char));
  if(a->user_id == NULL) return -14;
  memcpy(a->user_id, tmp_usrid, strlen(tmp_usrid));

  a->screen_name = (char *)calloc((strlen(tmp_usrname))+1, sizeof(char));
  if(a->screen_name == NULL) return -15;
  memcpy(a->screen_name, tmp_usrname, strlen(tmp_usrname));

  return 0;
}

int Twitter_UpdateStatus(struct Twitter_consumer_token *c,  struct Twitter_access_token *a, char *status)
{
  char buf[BUF_SIZE] = {'\0'};

  char oauth_signature_key[100] = {'\0'};

  struct timeval tv;
  char tstamp[20] = {'\0'};

  char nonce_tmp[20] = {'\0'};
  char nonce[20] = {'\0'};
  char nonce_urlenc[20] = {'\0'};

  char auth_tmpmsg[300 + TWEET_MAX_LENGTH] = {'\0'};//Temporary message for HMAC-SHA1
  char auth_encmsg[300 + (TWEET_MAX_LENGTH * ENCODED_CHAR_MARGIN)] = {'\0'};//Temporary message for HMAC-SHA1(URL-Encoded)
  char auth_postmsg[350 + (TWEET_MAX_LENGTH * ENCODED_CHAR_MARGIN)] = {'\0'};
  char encstatus[(TWEET_MAX_LENGTH * ENCODED_CHAR_MARGIN)] = {'\0'};

  char postmsg[400 + (TWEET_MAX_LENGTH * ENCODED_CHAR_MARGIN)] = {'\0'};//POST Header
  char reqheader[500 + (TWEET_MAX_LENGTH * ENCODED_CHAR_MARGIN)] = {'\0'};//POST Header

  char hmacmsg[40] = {'\0'};
  char b64msg[40] = {'\0'};

  char b64urlenc[50] = {'\0'};

  int i = 0;

  //Signature Key
  sprintf(oauth_signature_key, "%s&%s", c->consumer_secret, a->access_secret);

  //Get date, set as timestamp
  gettimeofday(&tv, NULL);
  sprintf(tstamp, "%ld", tv.tv_sec);

  //Set OAuth Nonce
  sprintf(nonce_tmp, "%ld", tv.tv_usec);
  base64_encode(nonce_tmp, strlen(nonce_tmp), nonce, 128);
  URLEncode(nonce, nonce_urlenc);

  //URL-Encode Tweet
  if(strlen(status) > TWEET_MAX_LENGTH) return -1;
  URLEncode(status, encstatus);

  //Generate OAuth Post message
  sprintf(auth_tmpmsg, "%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce_urlenc, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp,  OAUTH_TOKEN, a->access_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, OAUTH_VER_NUM, STATUS, encstatus);
  URLEncode(auth_tmpmsg, auth_encmsg);
  sprintf(auth_postmsg, "%s&%s&%s", MSG_POST, STATUS_UPDATE_ENCODED_URL, auth_encmsg);

  //Generate OAuth Signature
  hmac_sha1(oauth_signature_key, strlen(oauth_signature_key), auth_postmsg, strlen(auth_postmsg), hmacmsg);

  //Count Singnature length
  i=0;
  while(i<300) {
    if(hmacmsg[i] == 0 && hmacmsg[i+1] == 0 && hmacmsg[i+2] == 0) break;
    i++;
  }

  //Encode Signature text by BASE64, also URL Encode
  base64_encode(hmacmsg, i, b64msg, 128);
  URLEncode(b64msg, b64urlenc);

  //Generate POST Message
  sprintf(postmsg, "%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce_urlenc, OAUTH_SIG, b64urlenc, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp, OAUTH_TOKEN, a->access_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, OAUTH_VER_NUM, STATUS, encstatus);
  
  sprintf(reqheader, "POST %s %s\r\nHost: %s\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s\r\n\r\n", STATUS_UPDATE_URL, HTTP_VER, HOSTNAME, CONTENT_TYPE, (int)strlen(postmsg), postmsg);
  
  //SSL Session
  SSL_send_and_recv((char *)HOSTNAME, reqheader, buf);
  
  return 0;
}
