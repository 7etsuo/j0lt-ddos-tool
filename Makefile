CC=gcc
CFLAGS=-Wall -Wextra -g
TARGET=j0lt
OBJS=j0lt.o io.o opts.o process_control.o my_resolvlist.o j0lt_attack.o j0lt_network.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

j0lt.o: j0lt.c io.h
	$(CC) $(CFLAGS) -c j0lt.c

io.o: io.c io.h
	$(CC) $(CFLAGS) -c io.c

opts.o: opts.c opts.h
	$(CC) $(CFLAGS) -c opts.c

process_control.o: process_control.c process_control.h
	$(CC) $(CFLAGS) -c process_control.c

my_resolvlist.o: my_resolvlist.c my_resolvlist.h
	$(CC) $(CFLAGS) -c my_resolvlist.c

j0lt_attack.o: j0lt_attack.c j0lt_attack.h
	$(CC) $(CFLAGS) -c j0lt_attack.c

j0lt_network.o: j0lt_network.c j0lt_network.h
	$(CC) $(CFLAGS) -c j0lt_network.c

clean:
	rm -f $(TARGET) $(OBJS)
