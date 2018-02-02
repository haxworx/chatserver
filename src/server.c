#include "chatserver.h"
#include "clients.h"

extern Server server;
extern bool enabled;

static int
_fd_max_get(void)
{
   struct rlimit limit;

   if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
     return -1;

   return limit.rlim_cur - 10;
}
static void
_sig_int_cb(int sig)
{
   enabled = false;
}

static void
_signals_set(void)
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

char *
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

void
server_sockets_purge(void)
{
   int i, j;
   struct pollfd **sockets = &server.sockets[0];
puts("GOING FOR IT!");
   int count = server.socket_count;
   for (i = 0; i < count; i++)
     {
printf("%d\n", sockets[i]->fd);
        if (sockets[i]->fd == -1)
          {
             for (j = i; j < server.socket_count; j++)
               sockets[j] = sockets[j + 1];
             printf("DELETED!");
             server.socket_count--;
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

   free(server.space);
   free(server.sockets);
}

void
server_init(uint16_t port)
{
   struct pollfd **tmp;
   struct sockaddr_in servername;
   int i, flags, reuseaddr = 1;

   memset(&server, 0, sizeof(Server));
   server.sockets = calloc(1, CLIENTS_MAX * sizeof(struct pollfd *));
   server.space = calloc(1, CLIENTS_MAX * sizeof(struct pollfd));

   tmp = &server.sockets[0];
   for (i = 0; i < CLIENTS_MAX; i++)
     {
        tmp[i] = &server.space[i];
     }

   server.clients = calloc(1, sizeof(Client *));

   server.sockets_max = _fd_max_get();

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
   
   _signals_set();
   server_motd_get();

   server.sockets_purge = &server_sockets_purge;
   server.timeout_check = &clients_timeout_check;
   server.client_read = &client_read;
   server.motd_send = &client_motd_client_send;
   server.help_send = &client_help_send;
   server.shutdown = &server_shutdown;
}

