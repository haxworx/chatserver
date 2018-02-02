#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* Obv just an example auth implementation */

typedef struct {
   const char *username;
   const char *password;
} Credentials;

Credentials known_users[] = {
    { .username = "al",    .password = "letmein" },
    { .username = "peter", .password = "yeah" },
    { .username = "sue",   .password = "cheese" },
    { .username = "jim",   .password = "slim" },
};

int credentials_check(const char *username, const char *guess)
{
   int i = 0;

   while (i < sizeof(known_users) / sizeof(Credentials))
     {
        Credentials *user = &known_users[i++];
        if (!strcasecmp(user->username, username) &&
            !strcmp(user->password, guess))
          {
             return  0;
          }
     }

   return 1;
}

int main(void)
{
   char *user, *end, *guess;
   char buf[4096], byte[1];
   int i = 0;

   while (read(STDIN_FILENO, byte, sizeof(byte)) > 0)
     {
        buf[i++] = byte[0];
        if (i == sizeof(buf) -1)
          break;
     }

   buf[i] = 0x00;

   user = &buf[0];
   end = strchr(buf, ' ');
   if (!end) return 1;

   guess = strchr(buf, ' ') + 1;
   if (guess && guess[0])
     { 
        *end = '\0';
        end = strrchr(guess, '\r'); if (!end) end = strrchr(guess, '\n');
        if (end) *end = '\0';
        return credentials_check(user, guess);
     }
   return 1;
}

