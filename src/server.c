#include "chatserver.h"
#include "clients.h"
#include "server.h"

extern Server server;

static int
_fd_max_get(void)
{
   struct rlimit limits;

   if (getrlimit(RLIMIT_NOFILE, &limits) < 0)
     return -1;

   return limits.rlim_max;
}

static void
server_fd_max_set(void)
{
   int max, current = _fd_max_get();

   if (current < 0)
     {
        server.sockets_max = 128;
        return;
     }

   if (current >= 4096)
     max = 4096;
   else if (current >= 3128)
     max = 3128;
   else if (current >= 2048)
     max = 2048;
   else if (current >= 1024)
     max = 1024;
   else if (current >= 512)
     max = 512;
   else if (current >= 256)
     max = 256;
   else
     max = 128;

   struct rlimit limits = { max, max };

   setrlimit(RLIMIT_NOFILE, &limits);

   getrlimit(RLIMIT_NOFILE, &limits);

   server.sockets_max = limits.rlim_cur - 10;
}

static void
_sig_int_cb(int sig)
{
   server.enabled = false;
}

static void
server_signal_actions_set(void)
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
}

void
server_motd_path_set(const char *path)
{
   server.motd_path = path;
}

const char *
server_motd_path_get(void)
{
   return server.motd_path;
}

char *
server_motd_get()
{
   FILE *f;
   struct stat st;
   int size;
   char buffer[4096];
   ssize_t bytes, total = 0;
   static char *motd = NULL;
   const char *path = server_motd_path_get();

   if (!path) return NULL;

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

void
server_sockets_check(void)
{
   int i;
   struct pollfd *sockets = server.sockets;

   server.socket_count = 0;

   for (i = 0; i < server.sockets_max; i++)
     {
        if (sockets[i].fd != -1)
          {
             server.socket_count++;
          }
     }
}

void
server_shutdown(void)
{
   char *motd = server_motd_get();
   if (motd)
     free(motd);
   
   clients_free(server.clients);
   close(server.sock);
   free(server.sockets);
}

void
server_main_loop(void)
{
   Client **clients, *client;
   sigset_t newmask, oldmask;
   struct pollfd *sockets;
   int i, res;

   sockets = server.sockets;
   clients = server.clients;

   sigemptyset(&newmask);
   sigaddset(&newmask, SIGINT);

   while (server.enabled)
      {
         if (server.clients_deleted || server.clients_added)
           {
              server.sockets_check();
              server.clients_deleted = server.clients_added = false;
              printf("\rtotal socks: %5d clients: %5d ", server.socket_count, server.socket_count - 1);
              fflush(stdout);
           }

         sigprocmask(SIG_BLOCK, &newmask, &oldmask);
         if ((res = poll(sockets, server.sockets_max, 1000 / 4)) < 0)
           {
              exit(ERR_SELECT_FAILED);
           }
         sigprocmask(SIG_UNBLOCK, &oldmask, NULL);

         if (res == 0)
            {
               server.timeout_check(clients);
               continue;
            }

         for (i = 0; i < server.sockets_max; i++)
           {
              if (sockets[i].revents == 0) continue;

              if (sockets[i].fd == server.sock)
                {
                   server_accept();
                }
              else
                {
                   client = client_by_fd(clients, sockets[i].fd);
                   if (!client) { break; }

                   res = server.client_read(client);
                   if (res < 0) {}
                   else if (res == CLIENT_STATE_DISCONNECTED)
                     {
                        server.clients_del(clients, client);
                     }
                   else
                     {
                        if (server.request_parse(clients, client))
                          server.success_send(client);
                        else
                          server.failure_send(client);

                        if (client->state == CLIENT_STATE_DISCONNECT)
                          {
                             server.clients_del(clients, client);
                          }
                     }
                }
           }
      }
}

void
server_accept(void)
{
   Client *client;
   struct sockaddr_in clientname;
   int sock;
   socklen_t size;

   do {
         size = sizeof(clientname);
         sock = accept(server.sock, (struct sockaddr *) &clientname, &size);
         if (sock < 0)
           {
              if (errno == EAGAIN || errno == EMFILE ||
                  errno == ENFILE || errno == EINTR)
                {
                   break;
                }
              else
                {
                   exit(ERR_ACCEPT_FAILED);
                }
           }

         if (server.socket_count >= server.sockets_max)
           {
              close(sock);
              break;
           }

         client = server.clients_add(server.clients, sock);
         if (client)
           {
              server.motd_send(client);
           }
   } while (1);
}

void
server_init(uint16_t port)
{
   struct sockaddr_in servername;
   int i, flags, reuseaddr = 1;

   memset(&server, 0, sizeof(Server));
   server.sockets = calloc(1, CLIENTS_MAX * sizeof(struct pollfd));

   for (i = 0; i < CLIENTS_MAX; i++)
     {
        server.sockets[i].fd = -1;
     }

   if ((server.sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
     {
        exit(ERR_SOCKET_FAILED);
     }

   server.port = port;

   memset(&servername, 0, sizeof(servername));
   servername.sin_family = AF_INET;
   servername.sin_port = htons(port);
   servername.sin_addr.s_addr = INADDR_ANY;

   if (setsockopt(server.sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0)
     {
        exit(ERR_SETSOCKOPT_FAILED);
     }

   flags = fcntl(server.sock, F_GETFL, 0);
   fcntl(server.sock, F_SETFL, O_NONBLOCK | flags);

   if (bind(server.sock, (struct sockaddr *) &servername, sizeof(servername)) < 0)
     {
         exit(ERR_BIND_FAILED);
     }
   
   if (listen(server.sock, 5) < 0)
     {
        exit(ERR_LISTEN_FAILED);
     }

   server.sockets[0].fd = server.sock;
   server.sockets[0].events = POLLIN;
   server.socket_count = 1;

   server_fd_max_set();
   server_signal_actions_set();
   server_motd_path_set("./MOTD");

   server.clients = calloc(1, sizeof(struct pollfd) * CLIENTS_MAX);

   server.enabled = true;

   /* Function pointers */
   server.clients_add = &clients_add;
   server.clients_del = &clients_del;

   server.success_send = &client_command_success;
   server.failure_send = &client_command_failure;

   server.request_parse = &client_request;

   server.run = &server_main_loop;
   server.accept_or_deny = &server_accept;
   server.sockets_check = &server_sockets_check;
   server.timeout_check = &clients_timeout_check;
   server.client_read = &client_read;
   server.motd_send = &client_motd_client_send;
   server.help_send = &client_help_send;
   server.shutdown = &server_shutdown;
}

