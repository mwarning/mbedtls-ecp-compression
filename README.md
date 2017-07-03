# ECC Point compression/decompression for mbedtls

This is all about two helper methods called mbedtls_ecp_decompress() and mbedtls_ecp_compress().
They perform X25519 / Curve25519 point compression and decompression.
As of mbedtls 2.5.1, mbedtls does not support decompression.

The code is currently buggy and performs correctly half of the time!
It would be great if someone spots the bug. :-)
