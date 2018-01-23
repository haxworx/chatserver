CFLAGS=-Wall -pedantic -O0 -g -ggdb3
default:
	$(CC) $(CFLAGS) chatserver.c -o chatserver
clean:
	-rm chatserver
