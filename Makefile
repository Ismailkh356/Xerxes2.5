CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -D_DEFAULT_SOURCE
LDFLAGS = -lnghttp2 -lssl -lcrypto -pthread

TARGET = doser_advanced
SOURCES = doser_advanced.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

install:
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
