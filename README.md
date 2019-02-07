# Elliptic Curve Point compression/decompression for mbedTLS

This is all about two helper methods called `mbedtls_ecp_decompress()` and `mbedtls_ecp_compress()`.
They perform X25519 / Curve25519 point compression and decompression.
mbedTLS will likely never support decompression, as it is not mandated in the TLS specification.

This code has been placed into the Public Domain.

## Supported Curves

Only curves `3 mod 4` are supported:

- secp521r1
- brainpoolP512r1
- secp384r1
- brainpoolP384r1
- secp256r1
- secp256k1
- brainpoolP256r1
- secp192r1
- secp192k1

See [this post](https://github.com/ARMmbed/mbedtls/pull/521#discussion_r).

## Resources:
- https://github.com/ARMmbed/mbedtls/pull/521
- https://crypto.stackexchange.com/questions/6777/how-to-calculate-y-value-from-yy-mod-prime-efficiently
- http://www.secg.org/SEC2-Ver-1.0.pdf
