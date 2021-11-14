
#include <string.h>

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"

#include "ecc_point_compression.h"

/*
* Test for mbedtls_ecp_decompress() and mbedtls_ecp_compress()
*/


// Helper to convert binary to hex
static char *bytes_to_hex(const uint8_t bin[], size_t len)
{
    static const char hexchars[16] = "0123456789abcdef";
    static char hex[512];
    size_t i;

    for (i = 0; i < len; ++i)
    {
        hex[2 * i] = hexchars[bin[i] / 16];
        hex[2 * i + 1] = hexchars[bin[i] % 16];
    }
    hex[2 * len] = '\0';
    return hex;
}

// Helper to print public keys
static void dump_pubkey(const char *title, mbedtls_ecdsa_context *key)
{
    uint8_t buf[512];
    size_t len;

    if (mbedtls_ecp_point_write_binary(&key->grp, &key->Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof(buf)) != 0) {
        printf("internal error\n");
        return;
    }

    printf("%s %s (%d bits)\n", title, bytes_to_hex(buf, len), (int) key->grp.pbits);
}

#if 0
// Helper to print bignums
static void print_mpi(const char *title, const mbedtls_mpi *n) {
    char buf[512];
    size_t olen = 0;
    if (mbedtls_mpi_write_string(n, 16, buf, sizeof(buf), &olen) != 0) {
        printf("print_mpi error\n");
        exit(1);
    }

    printf("%s %s\n", title, buf);
}

// Helper to check if this holds for prime P: curve->p == 3 (mod 4)
static void check_prime(mbedtls_mpi *P){
    mbedtls_mpi tmp;
    mbedtls_mpi _4;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&_4);

    mbedtls_mpi_lset(&_4, 4);
    mbedtls_mpi_copy(&tmp, P);

    mbedtls_mpi_mod_mpi(&tmp, &tmp, &_4);
    print_mpi("We can use fast sqrt mod P if the output is 3: ", &tmp);
}
#endif

/*
* Test mbedtls_ecp_compress() / mbedtls_ecp_decompress() by signing a hash and
* transfering the public key in its compressed form from ctx_sign to ctx_verify.
*/
int test(int ecparams)
{
    int ret;
    mbedtls_pk_context ctx_verify;
    mbedtls_pk_context ctx_sign;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[] = "This should be the hash of a message.";
    unsigned char sig[512] = { 0 };
    size_t sig_len;
    const char *pers = "ecdsa";

    mbedtls_pk_init(&ctx_sign);
    mbedtls_pk_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    printf("Seeding the random number generator...\n");
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char *) pers, strlen(pers))) != 0)
    {
        printf("mbedtls_ctr_drbg_seed returned %d\n", ret);
        return(1);
    }

    printf("Generating key pair...\n");

    if ((ret = mbedtls_pk_setup(&ctx_sign, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
    {
        printf("mbedtls_pk_setup returned -0x%04x", -ret);
        return(1);
    }

    if ((ret = mbedtls_ecp_gen_key(ecparams, mbedtls_pk_ec(ctx_sign),
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("mbedtls_ecp_gen_key returned %d\n", ret);
        return(1);
    }
 
    dump_pubkey("Public key: ", mbedtls_pk_ec(ctx_sign));

    printf("Signing message...\n");

    if ((ret = mbedtls_ecdsa_write_signature(mbedtls_pk_ec(ctx_sign), MBEDTLS_MD_SHA256,
            hash, sizeof(hash), sig, sizeof(sig), &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("mbedtls_ecdsa_genkey returned %d\n", ret);
        return(1);
    }

    printf("ok (signature length = %lu)\n", sig_len);
    printf(" + Hash: %s\n", bytes_to_hex(hash, strlen((char*) hash)));
    printf(" + Signature: %s\n", bytes_to_hex(sig, sig_len));

    printf("Preparing verification context...\n");

    unsigned char buf[300];
    size_t buflen = 0;

    if ((ret = mbedtls_pk_setup(&ctx_verify, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
    {
        printf("mbedtls_pk_setup returned -0x%04x", -ret);
        return(1);
    }

    mbedtls_ecp_group_load(&mbedtls_pk_ec(ctx_verify)->grp, ecparams);

    // MBEDTLS_ECP_PF_COMPRESSED is supported here!
    if ((ret = mbedtls_ecp_point_write_binary(&mbedtls_pk_ec(ctx_sign)->grp,
            &mbedtls_pk_ec(ctx_sign)->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &buflen,
            buf, sizeof(buf))) != 0)
    {
        printf("mbedtls_ecp_point_write_binary returned: %d\n", ret);
        return(1);
    }

    {
        printf("Perform key transformations...\n");

        size_t compressed_len;
        unsigned char compressed[512];

        // We have the uncompressed key
        printf("starting point:         %s\n", bytes_to_hex(buf, buflen));

        // compress key from buf to compressed
        ret = mbedtls_ecp_compress(&mbedtls_pk_ec(ctx_verify)->grp, buf, buflen,
            compressed, &compressed_len, sizeof(compressed));
        printf("mbedtls_ecp_compress:   %s\n", bytes_to_hex(compressed, compressed_len));

        // decompress key from compressed back into buf
        memset(buf, 0, sizeof(buf)); // Make sure we don't cheat :)
        ret = mbedtls_ecp_decompress(&mbedtls_pk_ec(ctx_verify)->grp, compressed, compressed_len,
            buf, &buflen, sizeof(buf));
        printf("mbedtls_ecp_decompress: %s\n", bytes_to_hex(buf, buflen));
    }

    // MBEDTLS_ECP_PF_COMPRESSED format is _not_ supported here!
    if ((ret = mbedtls_ecp_point_read_binary(&mbedtls_pk_ec(ctx_verify)->grp,
            &mbedtls_pk_ec(ctx_verify)->Q, buf, buflen)) != 0)
    {
        printf("mbedtls_ecp_point_read_binary returned: %d\n", ret);
        exit(1);
    }

    printf("Verifying signature...\n");

    if ((ret = mbedtls_ecdsa_read_signature(mbedtls_pk_ec(ctx_verify),
            hash, sizeof(hash), sig, sig_len)) != 0)
    {
        printf("mbedtls_ecdsa_read_signature returned %d\n", ret);
        exit(1);
    }
    else
    {
        printf("Signature is valid!\n");
    }

    mbedtls_pk_free(&ctx_verify);
    mbedtls_pk_free(&ctx_sign);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}

int main(int argc, char **argv) {
    /*
    * Test point compression and decompression.
    * This implementation only works for curves where curve->p == 3 (mod 4) holds,
    * such as NIST / Brainpool / "Koblitz" curves used in mbedtls.
    */
    return test(MBEDTLS_ECP_DP_SECP256R1);
}
