/* extract.h
 * (C)2013-14 Plemling138
 */

 #ifndef _EXTRACT_H_
#define _EXTRACT_H_

int MakeSkipTable(char *key, int *skiptable, int length);
int ExtractQuery(char *text, char *key, char *buff);

#endif
