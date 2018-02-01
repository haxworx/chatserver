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

#define SERVER_MOTD_FILE_PATH "./MOTD"

static bool enabled = true;

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
#define CLIENT_TIMEOUT_CONNECTION 100
#define CLIENT_TIMEOUT_AUTHENTICATED 5 * 60

typedef enum {
   CLIENT_STATE_CONNECTED     = (0 << 0),
   CLIENT_STATE_IDENTIFIED    = (1 << 0),
   CLIENT_STATE_AUTHENTICATED = (1 << 1),
   CLIENT_STATE_DISCONNECT    = (1 << 2),
   CLIENT_STATE_IGNORE        = (1 << 4),
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

static struct pollfd _sockets[CLIENTS_MAX];
static int socket_count = 0;

static int
credentials_check(const char *username, char *guess)
{
   FILE *p;
   struct sigaction newaction, oldaction;
   char cmdstring[1024];
   int i, status = 0;

   sigemptyset(&newaction.sa_mask);
   newaction.sa_flags = 0;
   newaction.sa_handler = SIG_DFL;
   sigaction(SIGCHLD, NULL, &oldaction);
   sigaction(SIGCHLD, &newaction, NULL);

   p = popen("./auth", "w");
   if (p)
     {
        snprintf(cmdstring, sizeof(cmdstring), "%s %s\n", username, guess);
        fwrite(cmdstring, 1, strlen(cmdstring), p);

        status = pclose(p);
        status = !WEXITSTATUS(status);
     }

   for (i = 0; i < strlen(guess); i++)
     {
        guess[i] = '\0';
     }

   for (i = 0; i < strlen(cmdstring); i++)
     {
        cmdstring[i] = '\0';
     }

   sigaction(SIGCHLD, &oldaction, NULL);

   return status;
}

static char *
_motd_get()
{
   const char *path = SERVER_MOTD_FILE_PATH;
   FILE *f;
   struct stat st;
   int size;
   char buffer[4096];
   ssize_t bytes, total = 0;
   static char *motd = NULL;

   if (motd) return motd;

   if (stat(path, &st) < 0)
     return NULL;

   size = st.st_size;

   if (!size) return NULL;

   f = fopen(path, "rb");
   if (!f) return NULL;

   motd = malloc(size * sizeof(char) + 1);

   while (size)
     {
        bytes = fread(buffer, 1, sizeof(buffer), f);
        total += bytes;
        memcpy(&motd[total - bytes], buffer, bytes);
        size -= bytes;
     }

   motd[total] = 0x00;

   fclose(f);

   return motd;
}

static bool
server_motd_client_send(Client *client)
{
   ssize_t total, size, bytes;
   const char *motd = _motd_get();

   if (!motd) return false;

   total = 0;
   size = strlen(motd);

   while (size)
     {
        bytes = write(client->fd, &motd[total], size);
        if (bytes == 0) break;
        if (bytes < 0)
          {
             if (errno == EAGAIN || errno == EINTR)
               continue;
             else
               return false;
          }
        size -= bytes;
        total += bytes;
     }
   write(client->fd, "\r\n\r\n", 4);

   return true;
}

static void
_sig_int_cb(int sig)
{
   enabled = false;
}

static int
_fd_max_get(void)
{
   struct rlimit limit;

   if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
     return -1;

   return limit.rlim_max;
}

static void
_fd_max_set(void)
{
   struct rlimit limit;
   int try, max;

   max =_fd_max_get();
   if (max < 0) return;

   if (max >= 4096)
     try = 3128;
   else if (max >= 3128)
     try = 2048;
   else
     try = 1024;

   limit.rlim_cur = try;
   setrlimit(RLIMIT_NOFILE, &limit);
}

static void
server_init(void)
{
   struct sigaction newaction, oldaction;

   /* Handle SIGINT gracefully */
   sigemptyset(&newaction.sa_mask);
   newaction.sa_flags = 0;
   newaction.sa_handler = _sig_int_cb;
   sigaction(SIGINT, NULL, &oldaction);
   if (oldaction.sa_handler != SIG_IGN)
     sigaction(SIGINT, &newaction, NULL);

   /* Handle SIGPIPE by ignoring it */
   sigemptyset(&newaction.sa_mask);
   newaction.sa_handler = SIG_IGN;
   sigaction(SIGPIPE, NULL, &oldaction);
   if (oldaction.sa_handler != SIG_IGN)
     sigaction(SIGPIPE, &newaction, NULL);

   _fd_max_set();
   _motd_get();
}

static void
server_shutdown(void)
{
   char *motd = _motd_get();
   if (motd)
     free(motd);
}

static Client *
clients_add(Client **clients, int fd, uint32_t unixtime)
{
   Client *c;

   _sockets[socket_count].fd = fd;
   _sockets[socket_count].events = POLLIN;
   socket_count++;

   c = clients[0];
   if (c == NULL)
     {
        clients[0] = c = calloc(1, sizeof(Client));
        c->fd = fd;
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
        c->unixtime = unixtime;
     }

   return c;
}

static void
clients_del(Client **clients, Client *client)
{
   Client *c, *prev;
   const char *goodbye = "Bye now!\r\n\r\n";

   write(client->fd, goodbye, strlen(goodbye));

   for (int i = 0; i < socket_count; i++)
     {
        if (_sockets[i].fd == client->fd)
          {
             close(_sockets[i].fd);
             _sockets[i].fd = -1;
          }
     }

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

static void
sockets_purge(void)
{
   int i, j;

   for (i = 0; i < socket_count; i++)
     {
        if (_sockets[i].fd == -1)
          {
             for (j = i; j < socket_count; j++)
               _sockets[j] = _sockets[j + 1];

             socket_count--;
          }
     }
}

static Client *
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
             c->unixtime < time(NULL) - CLIENT_TIMEOUT_CONNECTION) ||
            (c->state == CLIENT_STATE_AUTHENTICATED &&
             c->unixtime < time(NULL) - (CLIENT_TIMEOUT_AUTHENTICATED)))
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
   size_t len = strlen(username);

   if (!len || len > 32)
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
        if (c->state == CLIENT_STATE_AUTHENTICATED &&
            !strcasecmp(username, c->username))
          {
             return true;
          }
        c = c->next;
     }

   return false;
}

static void
client_command_failure(Client *client)
{
   write(client->fd, "FAIL!\r\n", 7);
}

static void
client_command_success(Client *client)
{
   write(client->fd, "OK!\r\n", 5);
}

static bool
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

static bool
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

static int
client_read(Client *client)
{
   char buf[4096];
   ssize_t bytes;

   do {
         bytes = read(client->fd, buf, sizeof(buf) - 1);
         if (bytes == 0)
           {
              return bytes;
           }
         else if (bytes < 0)
           {
              if (errno == EAGAIN || errno == EINTR)
                return bytes;
              else
                exit(ERR_READ_FAILED);
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

static void
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

static bool
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

static bool
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

static bool
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
        success = client_help_send(client);
     }
   else if (!strcasecmp(request, "MOTD"))
     {
        success = server_motd_client_send(client);
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

int main(int argc, char **argv)
{
   Client **clients, *client;
   sigset_t newmask, oldmask;

   struct sockaddr_in servername, clientname;
   int sock;
   socklen_t size;

   int flags, port, in, i, res, reuseaddr = 1;

   if (argc != 2)
     {
        usage();
     }

   port = atoi(argv[1]);

   server_init();

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

   flags = fcntl(sock, F_GETFL, 0);
   fcntl(sock, F_SETFL, O_NONBLOCK | flags);

   if (bind(sock, (struct sockaddr *) &servername, sizeof(servername)) < 0)
     {
         exit(ERR_BIND_FAILED);
     }
   
   if (listen(sock, 5) < 0)
     {
        exit(ERR_LISTEN_FAILED);
     }

   memset(_sockets, 0, sizeof(_sockets));

   clients = calloc(1, sizeof(Client *));

   sigemptyset(&newmask);
   sigaddset(&newmask, SIGINT);

   socket_count = 1;
   _sockets[0].fd = sock;
   _sockets[0].events = POLLIN;
 
   printf("PID %d listening on port %d\n", getpid(), port);

   while (enabled)
     {
         sigprocmask(SIG_BLOCK, &newmask, &oldmask);
         if ((res = poll(_sockets, socket_count, 1000 / 4)) < 0)
           {
              exit(ERR_SELECT_FAILED);
           }
         sigprocmask(SIG_UNBLOCK, &oldmask, NULL);

         if (res == 0)
           {
              clients_timeout_check(clients);
              continue;
           }

         bool deleted = false;

         int current_size = socket_count;

         for (i = 0; i < current_size; i++)
           {
              if (_sockets[i].revents == 0) continue;

              if (_sockets[i].fd == sock)
                 {
                    do {
                       size = sizeof(clientname);
                       in = accept(sock, (struct sockaddr *) &clientname, &size);
                       if (in < 0)
                         {
                            if (errno == EAGAIN || errno == EINTR)
                              {
                                 break;
                              }
                            else
                              {
                                 exit(ERR_ACCEPT_FAILED);
                              }
                         }

                       client = clients_add(clients, in, time(NULL));
                       server_motd_client_send(client);
                       } while (1);
                 }
               else
                 {
                    client = client_by_fd(clients, _sockets[i].fd);
                    if (!client) { break; }

                    res = client_read(client);
                    if (res == 0)
                      {
                         clients_del(clients, client);
                         deleted = true;
                      }
                    else if (res > 0)
                      {
                         if (client_request(clients, client))
                           client_command_success(client);
                         else
                           client_command_failure(client);

                        if (client->state == CLIENT_STATE_DISCONNECT)
                          {
                             clients_del(clients, client);
                             deleted = true;
                          }
                      }
                 }
           }

     if (deleted)
        sockets_purge();
   }

   clients_free(clients);
   close(sock);

   server_shutdown();

   return EXIT_SUCCESS;
}

