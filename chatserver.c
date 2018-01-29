#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>

#define SERVER_SOCKET_PATH "./socket"
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

#define SECOND 1000000
#define CLIENT_TIMEOUT_CHECK SECOND / 4

#define CLIENT_TIMEOUT_CONNECTION 10
#define CLIENT_TIMEOUT_AUTHENTICATED 5 * 60

typedef enum {
   CLIENT_STATE_CONNECTED     = (0 << 0),
   CLIENT_STATE_IDENTIFIED    = (1 << 0),
   CLIENT_STATE_AUTHENTICATED = (1 << 1),
   CLIENT_STATE_DISCONNECT    = (1 << 2),
   CLIENT_STATE_TRANSFER      = (1 << 3),
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

static fd_set _active_fd_set;

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
server_motd_get()
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
   const char *motd = server_motd_get();

   if (!motd) return false;

   total = 0;
   size = strlen(motd);

   while (size)
     {
        bytes = write(client->fd, &motd[total], size);
        if (bytes == 0) break;
        if (bytes < 0)
          {
             if (errno == EAGAIN || errno == EINTR) {}
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
server_init(void)
{
   unlink(SERVER_SOCKET_PATH);
   server_motd_get();
}

static void
server_shutdown(void)
{
   char *motd = server_motd_get();
   if (motd)
     free(motd);
}

static Client *
clients_add(Client **clients, int fd, uint32_t unixtime)
{
   Client *c;

   FD_SET(fd, &_active_fd_set);

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

   FD_CLR(client->fd, &_active_fd_set);
   close(client->fd);

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
   char *tmp, buf[4096];
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
   else if (!strncasecmp(request, "NICK", 4) &&
            client->state != CLIENT_STATE_IDENTIFIED &&
            client->state != CLIENT_STATE_AUTHENTICATED)
     {
        success = client_identify(clients, client);
     }
   else if (!strncasecmp(request, "PASS", 4) &&
            client->state == CLIENT_STATE_IDENTIFIED)
     {
        success = client_authenticate(clients, client);
     }
   else if (!strcasecmp(request, "TRANSFER"))
     {
        if (client->state == CLIENT_STATE_AUTHENTICATED)
          client->state = CLIENT_STATE_TRANSFER;
        else
          success = false;
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
_twilight_zone(int fd)
{
   const char *msg = "You are in the twilight zone!!!\r\n";
   char buf[1024];
   ssize_t bytes;
   fd_set fdset;

   write(fd, msg, strlen(msg));

   FD_ZERO(&fdset);
   FD_SET(fd, &fdset);

   do {
      if (select(fd + 1, &fdset, NULL, NULL, NULL) < 0)
        {
           exit(ERR_SELECT_FAILED);
        }

      if (!FD_ISSET(fd, &fdset)) continue;

      bytes = read(fd, buf, sizeof(buf) -1);
      if (bytes < 0)
        {
           if (errno == EAGAIN || errno == EINTR) continue;
           else
             exit(ERR_READ_FAILED);
        }
      buf[bytes] = 0x00;
   } while (0);

   printf("client returns from twilight zone!!!\n");
}

static bool
_socket_pass(int socket, int fd)
{
   struct cmsghdr *cmsg;
   struct msghdr msg = { 0 };
   char buf[CMSG_SPACE(sizeof(int))];
   memset(buf, 0, sizeof(buf));

   struct iovec io;
   io.iov_base  = "";
   io.iov_len = 1;

   msg.msg_iov = &io;
   msg.msg_iovlen = 1;
   msg.msg_control = buf;
   msg.msg_controllen = sizeof(buf);

   cmsg = CMSG_FIRSTHDR(&msg);
   cmsg->cmsg_level = SOL_SOCKET;
   cmsg->cmsg_type = SCM_RIGHTS;
   cmsg->cmsg_len = CMSG_LEN(sizeof(int));

   memmove(CMSG_DATA(cmsg), &fd, sizeof(int));
   msg.msg_controllen = cmsg->cmsg_len;

   if (sendmsg(socket, &msg, 0) < 0)
     {
        return false;
     }

   return true;
}

static int
_socket_catch(int socket)
{
   struct cmsghdr *cmsg;
   int fd;
   struct msghdr msg = { 0 };
   char m_buffer[1], c_buffer[512];
   struct iovec io = { .iov_base = m_buffer, .iov_len = sizeof(m_buffer) };

   msg.msg_iov = &io;
   msg.msg_iovlen = 1;
   msg.msg_control = c_buffer;
   msg.msg_controllen = sizeof(c_buffer);

   if (recvmsg(socket, &msg, 0) < 0) return -1;

   cmsg = CMSG_FIRSTHDR(&msg);

   memmove(&fd, CMSG_DATA(cmsg), sizeof(int));

   return fd;
}

static void
_socket_pass_back(int fd)
{
   struct sockaddr_un unixname;
   int sock;

   if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
     {
        exit(EXIT_FAILURE);
     }

   memset(&unixname, 0, sizeof(unixname));
   unixname.sun_family = AF_UNIX;
   strncpy(unixname.sun_path, SERVER_SOCKET_PATH, 104);

   if (connect(sock, (struct sockaddr *) &unixname, sizeof(unixname)) < 0)
     {
        exit(EXIT_FAILURE);
     }

    _socket_pass(sock, fd);
}

static void
client_transfer_process_new(Client **clients, Client *client, void (*new_process)(int))
{
   int fds[2];

   if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) < 0)
     {
        return;
     }

   pid_t pid = fork();
   if (pid < 0) exit(EXIT_FAILURE);
   if (pid > 0)
     {
        close(fds[1]);
        if (_socket_pass(fds[0], client->fd))
          clients_del(clients, client);
     }
   else
     {
        close(fds[0]);
        int fd = _socket_catch(fds[1]);
        if (fd < 0)
          {
             exit(EXIT_FAILURE);
          }
        /* Free duplicated memory */
        char *motd = server_motd_get();
        if (motd) free(motd);
        clients_free(clients);

        /* Run the callback */
        new_process(fd);

        /* Return socket to main process */
        if (fd > 0)
          _socket_pass_back(fd);

        exit(EXIT_SUCCESS);
     }
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
   sigset_t newmask, oldmask;
   struct sigaction newaction, oldaction;
   struct timeval tv;
   fd_set read_fd_set;

   struct sockaddr_in servername, clientname;
   struct sockaddr_un unixname;
   int sock, sock_unix;
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

   memset(&unixname, 0, sizeof(unixname));
   unixname.sun_family = AF_UNIX;
   strncpy(unixname.sun_path, SERVER_SOCKET_PATH, 104);

   if ((sock_unix = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
     {
        exit(ERR_SOCKET_FAILED);
     }

   if (bind(sock_unix, (struct sockaddr *) &unixname, sizeof(unixname)) < 0)
     {
        exit(ERR_BIND_FAILED);
     }

   clients = calloc(1, sizeof(Client *));

   /* Handle SIGINT gracefully */
   sigemptyset(&newaction.sa_mask);
   newaction.sa_flags = 0;
   newaction.sa_handler = _sig_int_cb;
   sigaction(SIGINT, NULL, &oldaction);
   if (oldaction.sa_handler != SIG_IGN)
     sigaction(SIGINT, &newaction, NULL);

   /* Handle our zombies!!! */
   sigemptyset(&newaction.sa_mask);
   newaction.sa_flags = SA_NOCLDWAIT;
   newaction.sa_handler = SIG_DFL;
   sigaction(SIGCHLD, NULL, &oldaction);
   if (oldaction.sa_handler != SIG_IGN)
     sigaction(SIGCHLD, &newaction, NULL);

   sigemptyset(&newmask);
   sigaddset(&newmask, SIGINT);

   /* Configure select */
   tv.tv_sec = 0;
   tv.tv_usec = CLIENT_TIMEOUT_CHECK;

   FD_ZERO(&_active_fd_set);
   FD_SET(sock, &_active_fd_set);
   FD_SET(sock_unix, &_active_fd_set);
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
              if (i == sock_unix)
                {
                   int returner = _socket_catch(sock_unix);
                   if (returner < 0) break;

                   client = clients_add(clients, returner, time(NULL));
                   server_motd_client_send(client);
                }
              else if (i == sock)
                {
                   do {
                      size = sizeof(clientname);
                      in = accept(sock, (struct sockaddr *) &clientname, &size);
                      if (in < 0)
                        {
                           if (errno == EAGAIN || errno == EINTR)
                             break;
                           else
                             exit(ERR_ACCEPT_FAILED);
                        }

                      client = clients_add(clients, in, time(NULL));
                      server_motd_client_send(client);
                   } while (1);
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
                        if (client_request(clients, client))
                          client_command_success(client);
                        else
                          client_command_failure(client);

                        switch (client->state)
                          {
                             case CLIENT_STATE_TRANSFER:
                               client_transfer_process_new(clients, client, _twilight_zone);
                               break;
                             case CLIENT_STATE_DISCONNECT:
                               clients_del(clients, client);
                               break;
                             default:
                               break;
                          }
                     }
                   else { /* EAGAIN */ }
                }
           } /* End of FD_ISSET(i, &read_fd_set) */
       }
   } /* End of while (enabled) */

   clients_free(clients);
   close(sock);

   server_shutdown();

   return EXIT_SUCCESS;
}

