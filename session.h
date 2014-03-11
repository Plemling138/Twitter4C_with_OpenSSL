/* session.h - SSL session header
 * (C)2013-14 Plemling138
 */

#ifndef _SESSION_H_
#define _SESSION_H_

//Send-and-Recv Function
int SSL_send_and_recv(char *host, char *send_buf, char *recv_buf);

#endif
