CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

.PHONY: all clean

all: ktls_client

ktls_client: ktls_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f ktls_client
