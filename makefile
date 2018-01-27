CFLAGS=-Wall -pedantic -O0 -g -ggdb3
default:
	$(CC) $(CFLAGS) chatserver.c -o chatserver
	$(CC) $(CFLAGS) auth.c -o auth
clean:
	-rm chatserver
	-rm auth
	-rm socket
