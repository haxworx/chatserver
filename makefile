PROGRAM=chatserver
PROGRAM_AUTH=auth
CFLAGS=-Wall -pedantic -O0 -g -ggdb3
OBJECTS=main.o clients.o server.o auth.o
SRC_DIR=src

default: chatserver auth

chatserver: $(OBJECTS)
	$(CC) $(CFLAGS) *.o -o $(PROGRAM)

auth.o: $(SRC_DIR)/auth.c
	$(CC) -c $(CFLAGS) $(SRC_DIR)/auth.c -o $@
server.o: $(SRC_DIR)/server.c
	$(CC) -c $(CFLAGS) $(SRC_DIR)/server.c -o $@
clients.o: $(SRC_DIR)/clients.c
	$(CC) -c $(CFLAGS) $(SRC_DIR)/clients.c -o $@
main.o: $(SRC_DIR)/main.c
	$(CC) -c $(CFLAGS) $(SRC_DIR)/main.c -o $@


auth:
	$(CC) $(CFLAGS) $(SRC_DIR)/auth_main.c -o $(PROGRAM_AUTH)

clean:
	-rm $(PROGRAM)
	-rm $(PROGRAM_AUTH)
	-rm *.o
