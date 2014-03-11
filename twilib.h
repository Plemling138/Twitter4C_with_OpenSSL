/* twilib.h
 * (C)2013-14 Plemling138
 */

#ifndef _TWILIB_H_
#define _TWILIB_H_

#define BUF_SIZE 300
#define TWEET_LENGTH 150

#define MSG_POST "POST"

#define OAUTH_CONSKEY   "oauth_consumer_key="
#define OAUTH_NONCE     "oauth_nonce="
#define OAUTH_SIG       "oauth_signature="
#define OAUTH_SIGMETHOD "oauth_signature_method="
#define OAUTH_TSTAMP    "oauth_timestamp="
#define OAUTH_VER       "oauth_version="
#define OAUTH_TOKEN     "oauth_token="
#define OAUTH_VERIFIER  "oauth_verifier="

#define OAUTH_VER_NUM   "1.0"
#define HTTP_VER "HTTP/1.1"
#define HOSTNAME "api.twitter.com"
#define CONTENT_TYPE "application/x-www-form-urlencoded"
#define HMAC_SHA1 "HMAC-SHA1"
#define STATUS    "status="

#define REQUEST_TOKEN_URL "https://api.twitter.com/oauth/request_token"
#define ACCESS_TOKEN_URL  "https://api.twitter.com/oauth/access_token"
#define STATUS_UPDATE_URL "https://api.twitter.com/1.1/statuses/update.json"

#define REQUEST_TOKEN_ENCODED_URL "https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token"
#define ACCESS_TOKEN_ENCODED_URL  "https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token"
#define STATUS_UPDATE_ENCODED_URL "https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json"

/*Fit memory for Linux, and can use dynamic memory allocation*/
//#define USE_DYNAMIC_MEMORY_ALLOCATION
//#define USE_MULTIBYTE_CHAR

#ifndef USE_MULTIBYTE_CHAR
	#define ENCODED_CHAR_MARGIN 2
	#define MAX_LENGTH_MARGIN 1
#endif
#ifdef USE_MULTIBYTE_CHAR
	#define ENCODED_CHAR_MARGIN 2
	#define MAX_LENGTH_MARGIN 3
#endif

#ifndef USE_DYNAMIC_MEMORY_ALLOCATION
	#define USE_STATIC_MEMORY_ALLOCATION
	#define TWEET_MAX_LENGTH 140 * (MAX_LENGTH_MARGIN)
#endif


struct Twitter_consumer_token
{
  char *consumer_key;
  char *consumer_secret;
};

struct Twitter_request_token
{
  char *request_token;
  char *request_secret;
};

struct Twitter_access_token
{
  char *access_token;
  char *access_secret;
  char *user_id;
  char *screen_name;
  char *pin;
};

int Twitter_GetRequestToken(struct Twitter_consumer_token *c, struct Twitter_request_token *r);
int Twitter_GetAccessToken(struct Twitter_consumer_token *c, struct Twitter_request_token *r, struct Twitter_access_token *a);
int Twitter_UpdateStatus(struct Twitter_consumer_token *c, struct Twitter_access_token *a, char *status);
int Twitter_getUserStream(struct Twitter_consumer_token *c, struct Twitter_access_token *a);

#endif
