#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

/* Obv just an example auth implementation */

int
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

