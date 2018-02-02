#include "chatserver.h"
#include "clients.h"
#include "server.h"
#include "auth.h"

extern Server server;

Client *
clients_add(Client **clients, int fd, uint32_t unixtime)
{
   Client *c;
   struct pollfd *pfd, *sockets = server.sockets[0];

   pfd = &sockets[server.socket_count];
   sockets[server.socket_count].fd = fd;
   sockets[server.socket_count].events = POLLIN;
   server.socket_count++;

   c = clients[0];
   if (c == NULL)
     {
        clients[0] = c = calloc(1, sizeof(Client));
        c->fd = fd;
        c->pfd = pfd;
        c->unixtime = unixtime;
        return c;
     }

   while (c->next)
     c = c->next;

   if (c->next == NULL)
     {
        c->next = calloc(1, sizeof(Client));
        c = c->next;
        c->fd = fd;
        c->pfd = pfd;
        c->unixtime = unixtime;
     }

   return c;
}

void
clients_del(Client **clients, Client *client)
{
   Client *c, *prev;
   const char *goodbye = "Bye now!\r\n\r\n";

   write(client->fd, goodbye, strlen(goodbye));
   
   close(client->pfd->fd);

   client->pfd->fd = -1;

   printf("sock is %d\n", client->pfd->fd);
 
   server.clients_deleted = true;
 
   prev = NULL;
   c = clients[0];
   while (c)
     {
        if (c == client)
          {
             if (prev)
               {
                  prev->next = c->next;
               }
             else
               {
                  clients[0] = c->next;
               }

             free(c->data);
             free(c); c = NULL;

             return;
          }
        prev = c;
        c = c->next;
     }
}

Client *
client_by_username(Client **clients, const char *username)
{
   Client *c = clients[0];
   while (c)
     {
        if (c->state == CLIENT_STATE_AUTHENTICATED &&
            !strcasecmp(username, c->username))
          {
             return c;
          }
        c = c->next;
     }

   return NULL;
}

Client *
client_by_fd(Client **clients, int fd)
{
   Client *c = clients[0];
   while (c)
     {
       if (c->fd == fd)
         {
            return c;
         }
        c = c->next;
     }

   return NULL;
}

bool
clients_timeout_check(Client **clients)
{
   bool clients_deleted = false;
   Client *c = clients[0];
   while (c)
     {
        if ((c->state != CLIENT_STATE_AUTHENTICATED &&
             c->unixtime < time(NULL) - CLIENT_TIMEOUT_CONNECTION) ||
            (c->state == CLIENT_STATE_AUTHENTICATED &&
             c->unixtime < time(NULL) - (CLIENT_TIMEOUT_AUTHENTICATED)))
          {
             clients_del(clients, c);
             c = clients[0];
             clients_deleted = true;
             continue;
          }
        c = c->next;
     }

   return clients_deleted;
}

static bool
_username_valid(const char *username)
{
   int i;
   size_t len = strlen(username);

   if (!len || len > 32)
     return false;

   for (i = 0; i < len; i++)
     {
        if (isspace(username[i]) ||
           (!isalpha(username[i]) && !isdigit(username[i])))
          {
             return false;
          }
     }

   return true;
}

static bool
clients_username_exists(Client **clients, const char *username)
{
   Client *c = clients[0];
   while (c)
     {
        if (c->state == CLIENT_STATE_AUTHENTICATED &&
            !strcasecmp(username, c->username))
          {
             return true;
          }
        c = c->next;
     }

   return false;
}

void
client_command_failure(Client *client)
{
   write(client->fd, "FAIL!\r\n", 7);
}

void
client_command_success(Client *client)
{
   write(client->fd, "OK!\r\n", 5);
}

bool
client_identify(Client **clients, Client *client)
{
   char *potential;

   if (!strncasecmp(client->data, "NICK ", 5))
     {
        potential = strchr(client->data, ' ') + 1;
        if (potential && potential[0])
          {
             if (_username_valid(potential) &&
                 !clients_username_exists(clients, potential))
               {
                  snprintf(client->username, sizeof(client->username), "%s", potential);
                  client->state = CLIENT_STATE_IDENTIFIED;
                  return true;
               }
          }
     }

   return false;
}

bool
client_authenticate(Client **clients, Client *client)
{
   char *guess;

   if (!strncasecmp(client->data, "PASS ", 5))
     {
        guess = strchr(client->data, ' ') + 1;
        if (guess && guess[0])
          {
             if (credentials_check(client->username, guess))
               {
                  client->state = CLIENT_STATE_AUTHENTICATED;
                  return true;
               }
          }
     }

   return false;
}

int
client_read(Client *client)
{
   char buf[4096];
   ssize_t bytes;

   do {
         bytes = read(client->fd, buf, sizeof(buf) - 1);
         if (bytes == 0)
           {
              return CLIENT_STATE_DISCONNECTED;
           }
         else if (bytes < 0)
           {
              switch (errno)
                {
                   case EAGAIN:
                   case EINTR:
                      return bytes;
                   case ECONNRESET:
                      return CLIENT_STATE_DISCONNECTED;
                   default:
                      exit(ERR_READ_FAILED);
                }
           }
         else break;
   } while (0);

   client->unixtime = time(NULL);

   if (!client->data)
     {
        client->data = calloc(1, bytes * sizeof(char) + 1);
        client->len += bytes;
        memcpy(client->data, buf, bytes);
     }

   return bytes;
}

void
clients_active_list(Client **clients, Client *client)
{
   Client *c = clients[0];
   while (c)
     {
        if (c->state == CLIENT_STATE_AUTHENTICATED)
          {
             write(client->fd, c->username, strlen(c->username));
             write(client->fd, " ", 1);
          }
        c = c->next;
     }

   write(client->fd, "\r\n", 2);
}

bool
client_message_send(Client **clients, Client *client)
{
   Client *dest;
   char *to, *msg, *end;
   char buf[4096];

   if (client->state != CLIENT_STATE_AUTHENTICATED)
     return false;

   to = strchr(client->data, ' ') + 1;
   if (!to) return false;

   end = strchr(to, ' ');
   if (!end) return false;

   *end = '\0';

   msg = end + 1;
   if (!msg) return false;

   dest = client_by_username(clients, to);
   if (!dest) return false;

   snprintf(buf, sizeof(buf), "\r\n%s says: %s\r\n", client->username, msg);
   write(dest->fd, buf, strlen(buf));
#if defined(DEBUG)
   printf("user: %s says: %s to: %s\n", client->username, msg, to);
#endif

   return true;
}

bool
client_help_send(Client *client)
{
   char desc[4096];
   const char *request, *commands = "QUIT, NICK, PASS, LIST, MSG, MOTD, HELP.";

   write(client->fd, "\r\n", 2);

   request = strchr(client->data, ' '); 
   if (!request || !request[0])
     {
        snprintf(desc, sizeof(desc), "available commands: %s\r\n", commands);
        write(client->fd, desc, strlen(desc));
        return true;
     }

   request += 1;

   if (!strcasecmp(request, "NICK"))
     {
        snprintf(desc, sizeof(desc), "NICK: use desired username.\r\n");
     }
   else if (!strcasecmp(request, "PASS"))
     {
        snprintf(desc, sizeof(desc), "PASS: authenticate with password.\r\n");
     }
   else if (!strcasecmp(request, "LIST"))
     {
        snprintf(desc, sizeof(desc), "LIST: list connected and active users.\r\n");
     }
   else if (!strcasecmp(request, "MSG"))
     {
        snprintf(desc, sizeof(desc), "MSG: send message to desired user.\r\n");
     }
   else if (!strcasecmp(request, "MOTD"))
     {
        snprintf(desc, sizeof(desc), "MOTD: view server's message of the day.\r\n");
     }
   else if (!strcasecmp(request, "QUIT"))
     {
        snprintf(desc, sizeof(desc), "QUIT: quit this session.\r\n");
     }
   else
     {
        return false;
     }
  
   write(client->fd, desc, strlen(desc));

   return true;
}

bool
client_motd_client_send(Client *client)
{
   ssize_t total, size, bytes;
   const char *motd = server_motd_get();

   if (!motd) return false;

   total = 0;
   size = strlen(motd);

   while (size)
     {
        bytes = write(client->fd, &motd[total], size);
        if (bytes == 0)
          {
             break;
          }
        else if (bytes < 0)
          {
             if (errno == EAGAIN || errno == EINTR)
               {
                  continue;
               }
             else
               {
                  return false;
               }
          }
        size -= bytes;
        total += bytes;
     }

   write(client->fd, "\r\n\r\n", 4);

   return true;
}

static void
_client_data_trim(Client *client)
{
   char *end;

   client->data[client->len] = 0x00;

   end = strrchr(client->data, '\r'); if (!end) end = strrchr(client->data, '\n');
   if (end) *end = '\0';
}

static void
_client_data_free(Client *client)
{
   free(client->data);
   client->data = NULL;
   client->len = 0;
}

bool
client_request(Client **clients, Client *client)
{
   const char *request;
   bool success = true;

   _client_data_trim(client);

   request = client->data;

   if (!strcasecmp(request, "QUIT"))
     {
        client->state = CLIENT_STATE_DISCONNECT;
     }
   else if (!strncasecmp(request, "HELP", 4))
     {
        success = server.help_send(client);
     }
   else if (!strcasecmp(request, "MOTD"))
     {
        success = server.motd_send(client);
     }
   else if (!strcasecmp(request, "LIST"))
     {
        clients_active_list(clients, client);
     }
   else if (!strncasecmp(request, "MSG ", 4))
     {
        success = client_message_send(clients, client);
     }
   else if (!strncasecmp(request, "PASS", 4) &&
            (client->state == CLIENT_STATE_IDENTIFIED))
     {
        success = client_authenticate(clients, client);
     }
   else if (!strncasecmp(request, "NICK", 4) &&
            (client->state != CLIENT_STATE_IDENTIFIED) &&
            (client->state != CLIENT_STATE_AUTHENTICATED))
     {
        success = client_identify(clients, client);
     }
   else
     {
        success = false;
     }

   _client_data_free(client);

   return success;
}

void
clients_free(Client **clients)
{
   Client *next, *c = clients[0];

   while (c)
     {
        next = c->next;
        free(c->data);
        close(c->fd);

        free(c);
        c = next;
     }

   free(clients);
}

