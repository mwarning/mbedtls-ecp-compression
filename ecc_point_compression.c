
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

#define INC_MUL_COUNT

// Copied from mbedtls-2.4.2/library/ecp.c
#define MOD_MUL( N )    do { MBEDTLS_MPI_CHK( ecp_modp( &N, grp ) ); INC_MUL_COUNT } \
                        while( 0 )

// Copied from mbedtls-2.4.2/library/ecp.c
/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB( N )                                \
    while( N.s < 0 && mbedtls_mpi_cmp_int( &N, 0 ) != 0 )   \
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &N, &N, &grp->P ) )

// Copied from mbedtls-2.4.2/library/ecp.c
/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_add_mpi and mbedtls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                \
    while( mbedtls_mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( &N, &N, &grp->P ) )

// Copied from mbedtls-2.4.2/library/ecp.c
/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mbedtls_mpi *N, const mbedtls_ecp_group *grp )
{
    int ret;

    if( grp->modp == NULL )
        return( mbedtls_mpi_mod_mpi( N, N, &grp->P ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if( ( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 ) ||
        mbedtls_mpi_bitlen( N ) > 2 * grp->pbits )
    {
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    MBEDTLS_MPI_CHK( grp->modp( N ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &grp->P ) );

    while( mbedtls_mpi_cmp_mpi( N, &grp->P ) >= 0 )
        /* we known P, N and the result are positive */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( N, N, &grp->P ) );

cleanup:
    return( ret );
}

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

// Helper to check if this holds for prime P: curve->p == 3 (mod 4)
void check_prime(mbedtls_mpi *P){
    mbedtls_mpi tmp;
    mbedtls_mpi _4;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&_4);

    mbedtls_mpi_lset( &_4, 4 );
    mbedtls_mpi_copy(&tmp, P);

    mbedtls_mpi_mod_mpi(&tmp, &tmp, &_4);
    print_mpi("We can use fast sqrt mod P if the output is 3: ", &tmp);
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

    if( osize < *olen || ilen != (plen + 1) )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    if( input[0] != 0x02 && input[0] != 0x03 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    // 0x04+X+Y
    memcpy( output, input, ilen );
    output[0] = 0x04;

    mbedtls_mpi r;
    mbedtls_mpi x;
    mbedtls_mpi n;

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &x );
    mbedtls_mpi_init( &n );

    // x <= input
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &x, input + 1, plen ) );

    // r = x
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &r, &x ) );

    // r = x^2
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &r, &r, &x ) ); MOD_MUL( r );

    // r = x^2 + a
    if( grp->A.p == NULL ) {
        // Special case where a is -3
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &r, &r, 3 ) ); MOD_SUB( r );
    } else {
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &r, &r, &grp->A ) ); MOD_ADD( r );
    }

    // r = x^3 + ax
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &r, &r, &x ) ); MOD_MUL( r );

    // r = x^3 + ax + b
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &r, &r, &grp->B ) ); MOD_ADD( r );

    // r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

    // n = P + 1
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &n, &grp->P, 1 ) );

    // n = (P + 1) / 4
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &n, 2 ) );

    // r ^ ((P + 1) / 4)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &r, &r, &n, &grp->P, NULL ) );

    // Set sign
    MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &r, 0, input[0] & 1 ) );

    // y => output
    ret = mbedtls_mpi_write_binary( &r, output + 1 + plen, plen );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &x );
    mbedtls_mpi_free( &n );

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

    memcpy( output, input, *olen );

    // Set 0x02+X if Y is even, 0x03+X if Y is odd
    output[0] = 0x02 + (input[2 * plen] & 1);

cleanup:
    return( 0 );
}

/*
* Test mbedtls_ecp_compress() / mbedtls_ecp_decompress() by signing a hash and
* transfering the public key in its compressed form from ctx_sign to ctx_verify.
*/
int test( int ecparams ) {
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
        return( 1 );
    }

    printf( "Generating key pair...\n" );

    if( ( ret = mbedtls_pk_setup( &ctx_sign, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) ) != 0 )
    {
        printf( "mbedtls_pk_setup returned -0x%04x", -ret );
        return( 1 );
    }

    if( (ret = mbedtls_ecp_gen_key( ecparams, mbedtls_pk_ec( ctx_sign ),
        mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( "mbedtls_ecp_gen_key returned %d\n", ret );
        return( 1 );
    }
 
    dump_pubkey( "Public key: ", mbedtls_pk_ec( ctx_sign ) );

    printf( "Signing message...\n" );

    if( ( ret = mbedtls_ecdsa_write_signature( mbedtls_pk_ec( ctx_sign ), MBEDTLS_MD_SHA256,
            hash, sizeof( hash ), sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( "mbedtls_ecdsa_genkey returned %d\n", ret );
        return( 1 );
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
        return( 1 );
    }

    mbedtls_ecp_group_load( &mbedtls_pk_ec( ctx_verify )->grp, ecparams );

    // MBEDTLS_ECP_PF_COMPRESSED is supported here!
    if( ( ret = mbedtls_ecp_point_write_binary( &mbedtls_pk_ec( ctx_sign )->grp,
            &mbedtls_pk_ec( ctx_sign )->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &buflen,
            buf, sizeof(buf) )) != 0 )
    {
        printf( "mbedtls_ecp_point_write_binary returned: %d\n", ret );
        return( 1 );
    }

    {
        printf( "Perform key transform...\n" );

        size_t compressed_len;
        unsigned char compressed[512];

        // We have the uncompressed key
        printf( "decompressed:  %s\n", bytes_to_hex(buf, buflen) );

        // compress key from buf to compressed
        mbedtls_ecp_compress(&mbedtls_pk_ec(ctx_verify)->grp, buf, buflen,
            compressed, &compressed_len, sizeof(compressed));
        printf( "compressed:    %s\n", bytes_to_hex(compressed, compressed_len) );

        // decompress key from compressed back into buf
        memset(buf, 0, sizeof(buf)); // Make sure we don't cheat :)
        mbedtls_ecp_decompress(&mbedtls_pk_ec(ctx_verify)->grp, compressed, compressed_len,
            buf, &buflen, sizeof(buf));
        printf( "decompressed:  %s\n", bytes_to_hex(buf, buflen) );
    }

    // MBEDTLS_ECP_PF_COMPRESSED format is _not_ supported here!
    if( (ret = mbedtls_ecp_point_read_binary( &mbedtls_pk_ec( ctx_verify)->grp,
            &mbedtls_pk_ec(ctx_verify)->Q, buf, buflen )) != 0 )
    {
        printf( "mbedtls_ecp_point_read_binary returned: %d\n" );
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
        printf( "Signature is valid!\n" );
    }

    mbedtls_pk_free( &ctx_verify );
    mbedtls_pk_free( &ctx_sign );

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return 0;
}

int main(int argc, char **argv) {
    return test( MBEDTLS_ECP_DP_SECP192R1 );
}
