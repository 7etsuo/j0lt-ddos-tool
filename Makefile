CC=gcc
CFLAGS=-Wall -Wextra
TARGET=j0lt
OBJS=j0lt.o io.o opts.o process_control.o

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

clean:
	rm -f $(TARGET) $(OBJS)

