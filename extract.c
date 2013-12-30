/* extract.c - Extract query from received data
 * (C)2013-14 Plemling138
 */

#include <stdio.h>
#include <string.h>
#include "extract.h"

//Create skiptable for search query
int  MakeSkipTable(char *key, int *skiptable, int length) 
{
  int i;
  for(i=0;i<length-1;i++) {
    skiptable[i] = length-i-1;
  }

  skiptable[length-1] = length;

  for(i=length-2;i>=0;i--) {
    if(key[length-1] == key[i]) skiptable[length-1] = skiptable[i];
  }

  return 0;
}

//Extract query from received data
//(Using Boyer-Moore Algorithm)
int ExtractQuery(char *text, char *key, char *buff) {
  int textlen = 0, keylen=0;
  int i = 0, j = 0, search = 0, line = 0, cur = 0;
  int skiptable[100] = {0};
  textlen = strlen(text);
  keylen = strlen(key);
  MakeSkipTable(key, skiptable, keylen);
  
  for(i=0;i<textlen;i++) {
    if(text[i] == '\n') {
      line++;
      cur = 0;
    }
    
    for(search=0;search<keylen;search++) {
      if(text[i+search] != key[search]) break;
      else;
    }
    
    if(search == keylen) {
      break;
    }
    else cur++;
  }
  
  if(i == textlen) return -1;

  i += keylen;
  while(text[i] != '&' && text[i] != 0 && text[i] != ' ' && text[i] != '\r' && text[i] != '\n') {
    buff[j] = text[i];
    i++;
    j++;
  }
  
  return 0;
}
