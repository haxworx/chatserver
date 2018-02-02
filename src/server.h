#ifndef __SERVER_H__
#define __SERVER_H__

#include "chatserver.h"
#include "clients.h"

char *server_motd_get(void);
void server_sockets_purge(void);
void server_shutdown(void);
void server_init(uint16_t port);
void server_accept(void);
void server_main_loop(void);

#endif
