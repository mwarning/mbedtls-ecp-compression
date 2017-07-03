
all:
	gcc -g ecc_point_compression.c -lmbedtls -lmbedx509 -lmbedcrypto -o ecc_point_compression
