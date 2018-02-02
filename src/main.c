#include "chatserver.h"
#include "clients.h"
#include "server.h"

Server server;

static void
usage(void)
{
   printf("server <port>\n");

   exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
   if (argc != 2)
     {
        usage();
     }

   server_init(atoi(argv[1]));

   printf("PID %d listening on port %d, maximum clients %d\n",
          getpid(), server.port, server.sockets_max);

   server.run();

   server.shutdown();

   return EXIT_SUCCESS;
}

