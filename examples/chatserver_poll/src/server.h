#ifndef __SERVER_H__
#define __SERVER_H__

#include "chatserver.h"
#include "clients.h"

Server *server_new(void);
Server *server_self(void);
void server_shutdown(void);
void server_accept(void);
void server_run(void);
char *server_motd_get(void);
void server_port_set(int port);

#endif
