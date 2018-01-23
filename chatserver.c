#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

static bool enabled = true;

typedef enum {
   ERR_SOCKET_FAILED     = (1 << 0),
   ERR_SETSOCKOPT_FAILED = (1 << 1),
   ERR_BIND_FAILED       = (1 << 2),
   ERR_LISTEN_FAILED     = (1 << 3),
   ERR_SELECT_FAILED     = (1 << 4),
   ERR_ACCEPT_FAILED     = (1 << 5),
} Error_Network;

#define SECOND 1000000
#define CLIENT_TIMEOUT_CHECK SECOND / 4
#define CLIENT_TIMEOUT 10

typedef enum {
   CLIENT_STATE_CONNECTED     = (0 << 0),
   CLIENT_STATE_AUTHENTICATED = (1 << 0),
   CLIENT_STATE_DISCONNECT    = (1 << 1)
} Client_State;

typedef struct Client Client;
struct Client {
   Client_State state;
   char username[64];

   int fd;
   uint32_t unixtime;
   char *data;
   ssize_t len;
   Client *next;
};

static fd_set _active_fd_set;

static void
_file_contents_send(int fd, const char *path)
{
   FILE *f;
   struct stat st;
   char buffer[4096];
   int count, size;
   ssize_t bytes;

   if (stat(path, &st) < 0)
     return;

   f = fopen(path, "rb");
   if (!f)
     return;

   size = st.st_size;
 
   while (size)
     {
        count = fread(buffer, 1, sizeof(buffer), f);
        bytes = write(fd, buffer, count);
        if (bytes < count || bytes == 0)
          break;
        if (bytes < 0)
          exit(1 << 8);

        size -= bytes;
     }

   fclose(f);

   write(fd, "\r\n\r\n", 4);
}

static void
clients_add(Client **clients, int fd, uint32_t unixtime)
{
   int flags;
   Client *c = clients[0];

   FD_SET(fd, &_active_fd_set);
   flags = fcntl(fd, F_GETFL, 0);
   fcntl(fd, flags | O_NONBLOCK, F_SETFL);

   _file_contents_send(fd, "MOTD");

   c = clients[0];
   if (c == NULL)
     {
        clients[0] = c = calloc(1, sizeof(Client));
        c->fd = fd;
        c->unixtime = unixtime;
        return;
     }

   while (c->next)
     c = c->next;

   if (c->next == NULL)
     {
        c->next = calloc(1, sizeof(Client));
        c = c->next;
        c->fd = fd;
        c->unixtime = unixtime;
     }
}

static void
clients_del(Client **clients, Client *client)
{
   Client *c = clients[0];
   const char *goodbye = "Bye now!\r\n\r\n";

   write(client->fd, goodbye, strlen(goodbye));

   FD_CLR(client->fd, &_active_fd_set);
   close(client->fd);

   Client *prev = NULL;
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

static Client *
client_by_username(Client **clients, const char *username)
{
   Client *c = clients[0];
   while (c)
     {
        if (c->state != CLIENT_STATE_AUTHENTICATED)
          continue;

        if (!strcasecmp(username, c->username))
          {
             return c;
          }
        c = c->next;
     }

   return NULL;
}

static Client *
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

static void
clients_timeout_check(Client **clients)
{
   Client *c = clients[0];
   while (c)
     {
        if ((c->state != CLIENT_STATE_AUTHENTICATED &&
             c->unixtime < time(NULL) - CLIENT_TIMEOUT) ||
            (c->state == CLIENT_STATE_AUTHENTICATED &&
             c->unixtime < time(NULL) - (CLIENT_TIMEOUT * 100)))
          {
             clients_del(clients, c);
             c = clients[0];
             continue;
          }
        c = c->next;
     }
}

static bool
_username_valid(const char *username)
{
   int i;
   ssize_t len = strlen(username);

   if (len > 32)
     return false;

   for (i = 0; i < len; i++)
     {
        if (isspace(username[i]))
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
        if (!strcasecmp(username, c->username))
          {
             return true;
          }
        c = c->next;
     }

   return false;
}

static void
client_command_fail(Client *client)
{
   write(client->fd, "FAIL!\r\n", 7);
}

static void
client_command_success(Client *client)
{
   write(client->fd, "OK!\r\n", 5);
}

static void
client_authenticate(Client **clients, Client *client)
{
   char *potential;

   if (!strncasecmp(client->data, "NICK ", 5))
     {
        potential = strchr(client->data, ' ') + 1;
        if (potential)
          {
             if (!clients_username_exists(clients, potential) && _username_valid(potential))
               {
                  snprintf(client->username, sizeof(client->username), "%s", potential);
                  client->state = CLIENT_STATE_AUTHENTICATED;

                  client_command_success(client);
                  return;
               }
          }
     }

   client_command_fail(client);
}

static int
client_read(Client *client)
{
   char *tmp, buf[4096];
   ssize_t bytes;

   bytes = read(client->fd, buf, sizeof(buf) - 1);
   if (bytes <= 0)
     {
        return bytes;
     }

   client->unixtime = time(NULL);

   if (!client->data)
     {
        client->data = calloc(1, bytes * sizeof(char) + 1);
        client->len += bytes;
        memcpy(client->data, buf, bytes);
     }
   else
     {
        client->len += bytes;
        tmp = realloc(client->data, client->len * sizeof(bytes) + 1);
        if (tmp)
          {
             client->data = tmp;
             memcpy(&client->data[client->len - bytes], buf, bytes);
          }
     }

   return bytes;
}

static void
clients_active_list(Client **clients, int fd)
{
   Client *c = clients[0];
   while (c)
     {
        if (c->state == CLIENT_STATE_AUTHENTICATED)
          {
             write(fd, c->username, strlen(c->username));
             write(fd, " ", 1);
          }
        c = c->next;
     }

   write(fd, "\r\n", 2);
}

static void
client_message_send(Client **clients, Client *client)
{
   Client *dest;
   char *to, *msg, *end;
   char buf[4096];

   to = strchr(client->data, ' ') + 1;
   if (!to)
     {
        client_command_fail(client);     
        return;
     }

   end = strchr(to, ' ');
   if (!end)
     {
        client_command_fail(client);
        return;
     }

   *end = '\0';

   msg = end + 1;
   if (!msg)
     {
        client_command_fail(client);
        return;
     }

   dest = client_by_username(clients, to);
   if (!dest)
     {
        client_command_fail(client);
     }
   else
     {
        snprintf(buf, sizeof(buf), "%s says: %s\r\n", client->username, msg);
        write(dest->fd, buf, strlen(buf));
        client_command_success(client);
     }
#if defined(DEBUG)
   printf("user: %s says: %s to: %s\n", client->username, msg, to);
#endif
}

static void
client_help_send(Client *client)
{
   char desc[4096];
   const char *request, *commands = "QUIT, NICK, LIST, MSG, HELP.";

   write(client->fd, "\r\n", 2);

   request = strchr(client->data, ' '); 
   if (!request || !request[0] || !request[1])
     {
        snprintf(desc, sizeof(desc), "available commands: %s\r\n", commands);
        write(client->fd, desc, strlen(desc));
        return;
     }

   request += 1;

   if (!strncasecmp(request, "NICK", 4))
     {
        snprintf(desc, sizeof(desc), "NICK <USERNAME>.\r\n");
     }
   else if (!strncasecmp(request, "LIST", 4))
     {
        snprintf(desc, sizeof(desc), "LIST: list authenticated users.\r\n");
     }
   else if (!strncasecmp(request, "MSG", 3))
     {
        snprintf(desc, sizeof(desc), "MSG <USERNAME> <MESSAGE>.\r\n");
     }
   else if (!strncasecmp(request, "QUIT", 4))
     {
        snprintf(desc, sizeof(desc), "QUIT: quit this session.\r\n");
     }
   else
     {
        client_command_fail(client);
        return;
     }
  
   write(client->fd, desc, strlen(desc));
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

static int
client_request(Client **clients, Client *client)
{
   _client_data_trim(client);

   if (!strcasecmp(client->data, "QUIT"))
     {
        client->state = CLIENT_STATE_DISCONNECT;
     }
   else if (!strncasecmp(client->data, "HELP", 4))
     {
        client_help_send(client);
     }
   else if (!strcasecmp(client->data, "LIST"))
     {
        clients_active_list(clients, client->fd);
     }
   else if (!strncasecmp(client->data, "MSG ", 4))
     {
        client_message_send(clients, client);
     }
   else if (!strncasecmp(client->data, "NICK", 4) &&
            client->state != CLIENT_STATE_AUTHENTICATED)
     {
        client_authenticate(clients, client);
     }
   else
     {
        client_command_fail(client);
     }

   _client_data_free(client);

   return client->state;
}

static void
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

static void
usage(void)
{
   printf("server <port>\n");
   exit(EXIT_SUCCESS);
}

static void
_sig_int_cb(int sig)
{
   enabled = false;
}

int main(int argc, char **argv)
{
   Client **clients, *client;
   int port;
   struct sockaddr_in servername, clientname;
   int sock, in, i;
   socklen_t size;
   int flags, res, reuseaddr = 1;
   sigset_t newmask, oldmask;
   struct sigaction newaction, oldaction;
   struct timeval tv;
   fd_set read_fd_set;

   if (argc != 2)
     {
        usage();
     }

   port = atoi(argv[1]);

   if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
     {
        exit(ERR_SOCKET_FAILED);
     }

   memset(&servername, 0, sizeof(servername));
   servername.sin_family = AF_INET;
   servername.sin_port = htons(port);
   servername.sin_addr.s_addr = INADDR_ANY;

   if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0)
     {
        exit(ERR_SETSOCKOPT_FAILED);
     }

   if (bind(sock, (struct sockaddr *) &servername, sizeof(servername)) < 0)
     {
         exit(ERR_BIND_FAILED);
     }
   
   flags = fcntl(sock, F_GETFL, 0);
   fcntl(sock, flags | O_NONBLOCK);

   if (listen(sock, 5) < 0)
     {
        exit(ERR_LISTEN_FAILED);
     }

   clients = calloc(1, sizeof(Client *));

   /* Handle SIGINT gracefully */
   sigemptyset(&newaction.sa_mask);
   newaction.sa_flags = 0;
   newaction.sa_handler = _sig_int_cb;

   sigaction(SIGINT, NULL, &oldaction);
   if (oldaction.sa_handler != SIG_IGN)
     sigaction(SIGINT, &newaction, NULL);

   sigemptyset(&newmask);
   sigaddset(&newmask, SIGINT);

   /* Configure select */
   tv.tv_sec = 0;
   tv.tv_usec = CLIENT_TIMEOUT_CHECK;

   FD_ZERO(&_active_fd_set);
   FD_SET(sock, &_active_fd_set);

   printf("PID %d listening on port %d\n", getpid(), port);

   while (enabled) {
      read_fd_set = _active_fd_set;
      sigprocmask(SIG_BLOCK, &newmask, &oldmask);
      if ((res = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &tv)) < 0)
        {
           exit(ERR_SELECT_FAILED);
        }
      sigprocmask(SIG_UNBLOCK, &oldmask, NULL);

      if (res == 0)
        {
           clients_timeout_check(clients);
           tv.tv_sec = 0;
           tv.tv_usec = CLIENT_TIMEOUT_CHECK;
           continue;
        }

      for (i = 0; i < FD_SETSIZE; i++) {
         if (FD_ISSET(i, &read_fd_set))
           {
              if (i == sock)
                {
                   size = sizeof(clientname);
                   in = accept(sock, (struct sockaddr *) &clientname, &size);
                   if (in < 0)
                     {
                        exit(ERR_ACCEPT_FAILED);
                     }

                   clients_add(clients, in, time(NULL));
                }
              else 
                {
                   client = client_by_fd(clients, i);
                   if (!client) break;

                   res = client_read(client);
                   if (res == 0)
                     {
                        clients_del(clients, client);
                     }
                   else if (res > 0)
                     {
                        client_request(clients, client);
                        switch (client->state)
                          {
                             case CLIENT_STATE_DISCONNECT:
                               clients_del(clients, client);
                               break;
                             default:
                               break;
                          }
                     }
                   break;
                }
           }         
       }
   }

   clients_free(clients);
   close(sock);

   return EXIT_SUCCESS;
}

