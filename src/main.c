#include "chatserver.h"
#include "clients.h"
#include "server.h"

bool enabled = true;
Server server;

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
   struct pollfd *sockets;
   int i, res, current_size;

   if (argc != 2)
     {
        usage();
     }

   server_init(atoi(argv[1]));
   
   clients = server.clients;
   sockets = server.sockets[0];
   sockets[0].fd = server.sock;
   sockets[0].events = POLLIN;
   server.socket_count = 1;

   sigemptyset(&newmask);
   sigaddset(&newmask, SIGINT);

   printf("PID %d listening on port %d\n", getpid(), server.port);

   while (enabled)
     {
        if (server.clients_deleted)
          {
             server.sockets_purge();
          }
         
        printf("socks:  %d\n", server.socket_count);

        sigprocmask(SIG_BLOCK, &newmask, &oldmask);
        if ((res = poll(sockets, server.socket_count, 1000 / 4)) < 0)
          {
             exit(ERR_SELECT_FAILED);
          }
        sigprocmask(SIG_UNBLOCK, &oldmask, NULL);

        if (res == 0)
          {
             server.timeout_check(clients);
             continue;
          }

        current_size = server.socket_count;
        server.clients_deleted = false;

        for (i = 0; i < current_size; i++)
          {
             if (sockets[i].revents == 0) continue;

             if (sockets[i].fd == server.sock)
               {
                 do {
                       struct sockaddr_in clientname;
                       socklen_t size = sizeof(clientname);
                       int in = accept(server.sock, (struct sockaddr *) &clientname, &size);
                       if (in < 0)
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
                             close(in);
                             break;
                         }

                       client = clients_add(clients, in, time(NULL));
                       server.motd_send(client);
                    } while (1);
                 }
             else
               {
                  client = client_by_fd(clients, sockets[i].fd);
                  if (!client) { break; }

                  res = server.client_read(client);
                  if (res == CLIENT_STATE_DISCONNECTED)
                    {
                       clients_del(clients, client);
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
                         }
                    }
               }
          }
     }

   server.shutdown();

   return EXIT_SUCCESS;
}

