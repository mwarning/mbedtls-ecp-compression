# Elliptic Curve Point compression/decompression for mbedtls

This is all about two helper methods called mbedtls_ecp_decompress() and mbedtls_ecp_compress().
They perform X25519 / Curve25519 point compression and decompression.
mbedtls will likely never support decompression, as it is not mandated in the TLS specification.

This code has been placed into the Public Domain.

Resources:
- https://github.com/ARMmbed/mbedtls/pull/521
- https://crypto.stackexchange.com/questions/6777/how-to-calculate-y-value-from-yy-mod-prime-efficiently
- http://www.secg.org/SEC2-Ver-1.0.pdf
