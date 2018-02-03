#include "chatserver.h"
#include "clients.h"
#include "server.h"

static void
usage(void)
{
   printf("server <port>\n");

   exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
   Server *server;

   if (argc != 2)
     {
        usage();
     }

   server = server_new();
   if (!server)
     exit(EXIT_FAILURE);

   server_port_set(atoi(argv[1]));

   printf("PID %d listening on port %d, maximum clients %d\n",
          getpid(), server->port, server->sockets_max - 1);

   server_run();

   server_shutdown();

   return EXIT_SUCCESS;
}

