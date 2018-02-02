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
   int i, res;

   if (argc != 2)
     {
        usage();
     }

   server_init(atoi(argv[1]));
   
   sockets = server.sockets;
   sockets[0].fd = server.sock;
   sockets[0].events = POLLIN;
   server.socket_count = 1;
   clients = server.clients;

   sigemptyset(&newmask);
   sigaddset(&newmask, SIGINT);

   printf("PID %d listening on port %d, maximum clients %d\n", getpid(), server.port, server.sockets_max);

   while (enabled)
     {
        if (server.clients_deleted || server.clients_added)
          {
             server.sockets_check();
             server.clients_deleted = server.clients_added = false;
             printf("total socks: %d clients: %d\n", server.socket_count, server.socket_count - 1);
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

                       client = server.clients_add(clients, in);
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
                       server.clients_del(clients, client);
                    }
                  else if (res > 0)
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

   server.shutdown();

   return EXIT_SUCCESS;
}

