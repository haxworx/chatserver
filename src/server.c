#include "chatserver.h"
#include "clients.h"

extern Server server;
extern bool enabled;

static int
_fd_max_get(void)
{
   struct rlimit limits;

   if (getrlimit(RLIMIT_NOFILE, &limits) < 0)
     return -1;

   return limits.rlim_max;
}

static int
_fd_max_set(void)
{
   int max, current = _fd_max_get();

   if (current < 0)
     return 128;
   else if (current >= 4096)
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

   return limits.rlim_cur - 10;
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

   server.sockets_max = _fd_max_set();

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

   server.clients = calloc(1, sizeof(struct pollfd) * CLIENTS_MAX);

   server.clients_add = &clients_add;
   server.clients_del = &clients_del;

   server.success_send = &client_command_success;
   server.failure_send = &client_command_failure;

   server.request_parse = &client_request;

   server.sockets_check = &server_sockets_check;
   server.timeout_check = &clients_timeout_check;
   server.client_read = &client_read;
   server.motd_send = &client_motd_client_send;
   server.help_send = &client_help_send;
   server.shutdown = &server_shutdown;
}

