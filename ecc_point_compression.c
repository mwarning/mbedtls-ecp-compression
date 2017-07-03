
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"

/*
* This is all about mbedtls_ecp_decompress() and mbedtls_ecp_compress()
*
* Perform X25519 / Curve25519 point compression and decompression for mbedtls.
* As of mbedtls 2.5.1, mbedtls does not support decompression.
*
*/

// Helper to convert binary to hex
char *bytes_to_hex( const uint8_t bin[], size_t len ) {
    static const char hexchars[16] = "0123456789abcdef";
    static char hex[512];
    size_t i;

    for( i = 0; i < len; ++i ) {
        hex[2 * i] = hexchars[bin[i] / 16];
        hex[2 * i + 1] = hexchars[bin[i] % 16];
    }
    hex[2 * len] = '\0';
    return hex;
}

// Helper to print public keys
static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    uint8_t buf[512];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof(buf) ) != 0 )
    {
        printf("internal error\n");
        return;
    }

    printf("%s %s (%d bits)\n", title, bytes_to_hex( buf, len ), (int) key->grp.pbits);
}

// Helper to print bignums
void print_mpi(const char *title, const mbedtls_mpi *n) {
    char buf[512];
    size_t olen = 0;
    if(mbedtls_mpi_write_string( n, 16, buf, sizeof(buf), &olen ) != 0) {
        printf("print_mpi error\n");
        exit(1);
    }

    printf("%s %s\n", title, buf);
}

int mbedtls_ecp_decompress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
) {
    int ret;
    size_t plen;


    plen = mbedtls_mpi_size( &grp->P );

    *olen = 2 * plen + 1; 

    if( osize < *olen) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    if( ilen != (plen + 1)) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    if( input[0] != 0x02 && input[0] != 0x03) {
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    memcpy(output, input, ilen);
    output[0] = 0x04;

    mbedtls_mpi r;
    mbedtls_mpi x;
    mbedtls_mpi n;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&n);

    // x <= ...
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&x, input + 1, plen) );

    // r = x
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy(&r, &x) );

    // r = x^2
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi(&r, &r, &x) );

    // r = x^2 + a
    if( grp->A.p == NULL ) {
        // Special case where a is -3
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int(&r, &r, 3) );
    } else {
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi(&r, &r, &grp->A) );
    }

    // r = x^3 + ax
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi(&r, &r, &x ) );
    //mbedtls_mpi_mod_mpi(&r, &r, &grp->P);

    // r = x^3 + ax + b
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi(&r, &r, &grp->B) );
    //mbedtls_mpi_mod_mpi(&r, &r, &grp->P);

    // r = sqrt(x^3 + ax + b) = n
    // r = n ^ ((P + 1) / 4)
    //https://crypto.stackexchange.com/questions/6777/how-to-calculate-y-value-from-yy-mod-prime-efficiently
    // n = P + 1
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int(&n, &grp->P, 1) );
    // n = (P + 1) / 4
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r(&n, 2) );
    // ..
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL) );

    // set sign
    MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &r, 0, input[0] & 1 ) );

    ret = mbedtls_mpi_write_binary(&r, output + 1 + plen, plen);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&n);

    return( ret );
}

int mbedtls_ecp_compress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
) {
    size_t plen;

    plen = mbedtls_mpi_size( &grp->P );

    *olen = plen + 1;

    if( osize < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    memcpy(output, input, *olen);
    output[0] = 0x02 + (input[*olen] & 1);

cleanup:
    return( 0 );
}

/*
* Test mbedtls_ecp_compress() / mbedtls_ecp_decompress() by signing a hash and
* transfering the public key in its compressed form from ctx_sign to ctx_verify.
*/
int test(int ecparams) {
    int ret;
    mbedtls_pk_context ctx_verify;
    mbedtls_pk_context ctx_sign;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[] = "This should be the hash of a message.";
    unsigned char sig[512] = { 0 };
    size_t sig_len;
    const char *pers = "ecdsa";

    mbedtls_pk_init( &ctx_sign );
    mbedtls_pk_init( &ctx_verify );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    printf( "Seeding the random number generator...\n" );
    mbedtls_entropy_init( &entropy );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( "mbedtls_ctr_drbg_seed returned %d\n", ret );
        exit(1);
    }

    printf( "Generating key pair...\n" );

    if( ( ret = mbedtls_pk_setup( &ctx_sign, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) ) != 0 )
    {
        printf( "mbedtls_pk_setup returned -0x%04x", -ret );
        exit(1);
    }

    if( (ret = mbedtls_ecp_gen_key( ecparams, mbedtls_pk_ec( ctx_sign ),
        mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( "mbedtls_ecp_gen_key returned %d\n", ret );
        exit(1);
    }
 
    dump_pubkey( "Public key: ", mbedtls_pk_ec( ctx_sign ) );

    printf( "Signing message...\n" );

    if( ( ret = mbedtls_ecdsa_write_signature( mbedtls_pk_ec( ctx_sign ), MBEDTLS_MD_SHA256,
            hash, sizeof( hash ), sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( "mbedtls_ecdsa_genkey returned %d\n", ret );
        exit(1);
    }

    printf( "ok (signature length = %lu)\n", sig_len );
    printf( " + Hash: %s\n", bytes_to_hex(hash, strlen(hash)));
    printf( " + Signature: %s\n", bytes_to_hex(sig, sig_len));

    printf( "Preparing verification context...\n" );

    unsigned char buf[300];
    size_t buflen = 0;

    if( ( ret = mbedtls_pk_setup( &ctx_verify, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) ) != 0 )
    {
        printf( "mbedtls_pk_setup returned -0x%04x", -ret );
        exit(1);
    }

    mbedtls_ecp_group_load( &mbedtls_pk_ec( ctx_verify )->grp, ecparams );

    // MBEDTLS_ECP_PF_COMPRESSED is supported here!
    if( ( ret = mbedtls_ecp_point_write_binary( &mbedtls_pk_ec( ctx_sign )->grp,
            &mbedtls_pk_ec( ctx_sign )->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &buflen,
            buf, sizeof(buf) )) != 0 )
    {
        printf("mbedtls_ecp_point_write_binary returned: %d\n", ret);
        exit(1);
    }

    {
        printf("Perform key transform...\n");

        size_t compressed_len;
        unsigned char compressed[512];

        // We have the uncompressed key
        printf( "decompressed:  %s\n", bytes_to_hex(buf, buflen));

        // compress key from buf to compressed
        mbedtls_ecp_compress(&mbedtls_pk_ec(ctx_verify)->grp, buf, buflen,
            compressed, &compressed_len, sizeof(compressed));
        printf("compressed:    %s\n", bytes_to_hex(compressed, compressed_len) );

        // decompress key from compressed back into buf
        memset(buf, 0, sizeof(buf)); // Make sure we don't cheat :)
        mbedtls_ecp_decompress(&mbedtls_pk_ec(ctx_verify)->grp, compressed, compressed_len,
            buf, &buflen, sizeof(buf));
        printf("decompressed:  %s\n", bytes_to_hex(buf, buflen) );
    }

    // MBEDTLS_ECP_PF_COMPRESSED format is _not_ supported here!
    if( (ret = mbedtls_ecp_point_read_binary( &mbedtls_pk_ec( ctx_verify)->grp,
            &mbedtls_pk_ec(ctx_verify)->Q, buf, buflen )) != 0 )
    {
        printf("mbedtls_ecp_point_read_binary returned: %d\n");
        exit(1);
    }

    printf( "Verifying signature...\n" );

    if( (ret = mbedtls_ecdsa_read_signature( mbedtls_pk_ec(ctx_verify),
            hash, sizeof( hash ), sig, sig_len )) != 0 )
    {
        printf( "mbedtls_ecdsa_read_signature returned %d\n", ret );
        exit(1);
    }
    else
    {
        printf("Signature is valid!\n");
    }

    mbedtls_pk_free( &ctx_verify );
    mbedtls_pk_free( &ctx_sign );

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return 0;
}

int main(int argc, char **argv) {
    return test(MBEDTLS_ECP_DP_SECP192R1);
}
