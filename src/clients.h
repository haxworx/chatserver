#ifndef __CLIENTS_H__
#define __CLIENTS_H__

#include "chatserver.h"

typedef enum {
   CLIENT_STATE_DISCONNECTED  = (0 << 0),
   CLIENT_STATE_CONNECTED     = (1 << 1),
   CLIENT_STATE_DISCONNECT    = (1 << 2),
   CLIENT_STATE_IDENTIFIED    = (1 << 3),
   CLIENT_STATE_AUTHENTICATED = (1 << 4),
   CLIENT_STATE_IGNORE        = (1 << 5),
} Client_State;

typedef struct Client Client;
struct Client {
   Client_State state;
   char username[64];
   int fd;
   struct pollfd *pfd;

   uint32_t unixtime;
   char *data;
   ssize_t len;
   Client *next;
};

Client *clients_add(Client **clients, int fd, uint32_t unixtime);
void clients_del(Client **clients, Client *client);
Client *client_by_username(Client **clients, const char *username);
Client *client_by_fd(Client **clients, int fd);
bool clients_timeout_check(Client **clients);

void client_command_failure(Client *client);

void client_command_success(Client *client);

bool client_identify(Client **clients, Client *client);

bool client_authenticate(Client **clients, Client *client);

int client_read(Client *client);

void clients_active_list(Client **clients, Client *client);

bool client_message_send(Client **clients, Client *client);

bool client_help_send(Client *client);
bool client_request(Client **clients, Client *client);
void clients_free(Client **clients);
bool client_motd_client_send(Client *client);


#endif
