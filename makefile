CFLAGS=-Wall -pedantic -O0 -g -ggdb3
default:
	$(CC) $(CFLAGS) chatserver.c -o chatserver
	$(CC) $(CFLAGS) auth.c -o authtool
clean:
	-rm chatserver
	-rm authtool
