CC=gcc
CFLAGS=-Wall -Wextra
TARGET=j0lt
OBJS=j0lt.o io.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

j0lt.o: j0lt.c io.h
	$(CC) $(CFLAGS) -c j0lt.c

io.o: io.c io.h
	$(CC) $(CFLAGS) -c io.c

clean:
	rm -f $(TARGET) $(OBJS)