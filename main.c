/* main.c - Example Twitter client using Twitter4C
 * (C)2013-14 Plemling138
 */

/*
  Usage: 
  ./tweet [status]
  -Enable Multi-byte text
  -NOT package character count
  (Perhaps overflow buffer)
  
  -If Status-update success:
  return HTTP/1.0 200 and json data
  -If any:
  return HTTP Error code
*/ 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "twilib.h"

#define SHOW_RESPONSE 0

void RemoveReturn(char *str, int size)
{
  int i=0;
  while(str[i] != 0 && i != size) {
    if(str[i] == '\r' || str[i] == '\n') str[i] = 0;
    i++;
  }
}

int main(int argc, char *argv[])
{
  int errcode = 0;
  char pin[20] = {0};
  char *errcode_c = 0;
  FILE *access_token;

  char usr[20] = {0}, id[20] = {0}, token[150] = {0}, secret[150] = {0};
  
  if(argc != 2) {
    printf("Usage: ./tweet [Tweet text]\n");
    exit(0);
  }
  
  struct Twitter_consumer_token *c;
  struct Twitter_request_token *r;
  struct Twitter_access_token *a;

  c = (struct Twitter_consumer_token *) calloc(1, sizeof(struct Twitter_consumer_token));
  r = (struct Twitter_request_token *) calloc(1, sizeof(struct Twitter_request_token));
  a = (struct Twitter_access_token *) calloc(1, sizeof(struct Twitter_access_token));

  //Set Consumer Key and Consumer Secret
  char consumer_key[] = "[ENTER YOUR APPLICATION CONSUMER KEY]";
  char consumer_secret[] = "[ENTER YOUR APPLICATION CONSUMER SECRET]";

  c->consumer_key = consumer_key;
  c->consumer_secret = consumer_secret;

  //Save Access token
  access_token = fopen("access_token.txt", "r");
  
  //If Access token is not found, create new token
  if(access_token == NULL) {
    //Get Request token
    if(errcode = Twitter_GetRequestToken(c, r), errcode < 0) {
      printf("Failed to get Request token.\n");
      exit(errcode);
    }
    
	//Enter PIN code
    printf("\nPlease Access %s%s , enter PIN code.\nPIN:", "https://api.twitter.com/oauth/authorize?oauth_token=", r->request_token);
    if(scanf("%19s%*[^\n]", pin) == -1) exit(1);
    a->pin = pin;

	//Get Access token
    if(errcode = Twitter_GetAccessToken(c, r, a), errcode < 0) {
      printf("Failed to get Access token.\n");
      exit(errcode);
    }
    
    printf("\nWelcome, %s(ID:%s)!\n", a->screen_name, a->user_id);
    
	//Save Access token
    access_token = fopen("access_token.txt", "w");
    if(access_token == NULL) {
      printf("Failed to save Access token\n");
      exit(-1);
    }
    fprintf(access_token, "%s\n%s\n%s\n%s\n%s\n", a->screen_name, a->user_id, a->access_token, a->access_secret, a->pin);
    fclose(access_token);
  }
  //If Access token is exist, extract tokens
  else {
    if(errcode_c = fgets(usr, 20, access_token), errcode_c == NULL) return -1;
    if(errcode_c = fgets(id, 20, access_token), errcode_c == NULL) return -1;
    if(errcode_c = fgets(token, 150, access_token), errcode_c == NULL) return -1;
    if(errcode_c = fgets(secret, 150, access_token), errcode_c == NULL) return -1;
    if(errcode_c = fgets(pin, 20, access_token), errcode_c == NULL) return -1;
    
    RemoveReturn(usr, 20);
    RemoveReturn(id, 20);
    RemoveReturn(token, 150);
    RemoveReturn(secret, 150);
    RemoveReturn(pin, 20);
  
    a->user_id = usr;
    a->access_token = token;
    a->access_secret = secret;
    a->pin = pin;
    fclose(access_token);
  }
  
  //Update Status
  if(errcode = Twitter_UpdateStatus(c, a, argv[1]), errcode < 0) {
    printf("Failed to Update status.\n");
    exit(errcode);
  }
  else printf("Tweet successful!\n");
  
  return 0;
}
