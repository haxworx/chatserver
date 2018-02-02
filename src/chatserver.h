#ifndef __CHATSERVER_H__
#define __CHATSERVER_H__

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <poll.h>
#include <netinet/in.h>
#include "clients.h"

#define SERVER_MOTD_FILE_PATH "./MOTD"

extern bool enabled;

typedef enum {
   ERR_SOCKET_FAILED     = (1 << 0),
   ERR_SETSOCKOPT_FAILED = (1 << 1),
   ERR_BIND_FAILED       = (1 << 2),
   ERR_LISTEN_FAILED     = (1 << 3),
   ERR_SELECT_FAILED     = (1 << 4),
   ERR_ACCEPT_FAILED     = (1 << 5),
   ERR_READ_FAILED       = (1 << 6),
} Error_Network;

#define CLIENTS_MAX 4096
#define CLIENT_TIMEOUT_CONNECTION 10
#define CLIENT_TIMEOUT_AUTHENTICATED 5 * 60

typedef struct {
   int sock;
   uint16_t port;
   int socket_count;
   int sockets_max;
   bool clients_deleted;

   struct pollfd **sockets;
   struct pollfd *space;
   Client **clients;

   void (*shutdown)(void);
   bool (*timeout_check)(Client **clients);
   int (*client_read)(Client *client);
   bool (*motd_send)(Client *client);
   bool (*help_send)(Client *client);
   void (*sockets_purge)(void);

} Server;

#endif
