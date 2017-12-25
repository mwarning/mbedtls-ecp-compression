
CC ?= gcc
CFLAGS ?= -g -Wall -pedantic
CFLAGS += -std=gnu99
LFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto

all:
	$(CC) $(CFLAGS) -pedantic ecc_point_compression.c test.c $(LFLAGS) -o test
