#include <iostream>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
#include <unistd.h>

# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)     /* Base64 */
# define FORMAT_ASN1     4                      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8                      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPubicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPubicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */

# define EXT_COPY_NONE   0
# define EXT_COPY_ADD    1
# define EXT_COPY_ALL    2


#define DEFBITS 2048
#define DEFPRIMES 3

typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;

static int istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

static const char *modestr(char mode, int format)
{
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return istext(format) ? "a" : "ab";
    case 'r':
        return istext(format) ? "r" : "rb";
    case 'w':
        return istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

BIO *bio_open_owner(const char *filename, int format)
{
    FILE *fp = NULL;
    BIO *b = NULL;
    int fd = -1, bflags, mode, textmode;

    mode = O_WRONLY;
#ifdef O_CREAT
    mode |= O_CREAT;
#endif
#ifdef O_TRUNC
    mode |= O_TRUNC;
#endif

	textmode = istext(format);
	if(!textmode)
	{
#ifdef O_BINARY
        mode |= O_BINARY;
#elif defined(_O_BINARY)
        mode |= _O_BINARY;
#endif
	}

    fd = open(filename, mode, 0600);
	if(fd < 0)
	{
		goto err;
	}

    fp = fdopen(fd, modestr('w', format));
    if (fp == NULL)
	{
        goto err;
	}
	bflags = BIO_CLOSE;
    if (textmode)
	{
       bflags |= BIO_FP_TEXT;
	}

	b = BIO_new_fp(fp, bflags);
	if(b)
	{
		return b;
	}

 err:
	std::cout << "1. error" << std::endl;
    if (fp)
    	fclose(fp);
    else if (fd >= 0)
        close(fd);

    return NULL;
}

int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
	return 0;
}

int genras(char* outfile)
{
	BIO *out = NULL;
	RSA *rsa = NULL;
	const BIGNUM *e;
	char *prog, *hexe, *dece;
	int privake_key = 1;
	PW_CB_DATA cb_data;
	char *passout = NULL;
	const EVP_CIPHER *enc = NULL;
	unsigned long f4 = RSA_F4;
	BIGNUM *bn = BN_new();
	int ret = 1, num = DEFBITS, primes = 4;
	BN_GENCB *cb = BN_GENCB_new();

	out = bio_open_owner(outfile, FORMAT_PEM);
	if(out == NULL)
	{
		std::cout << "bio_open_owner error" << std::endl;
		return false;
	}


	rsa = RSA_new();
	if(rsa == NULL)
	{
		std::cout << "rsa error" << std::endl;
		goto end;
	}


    if (!BN_set_word(bn, f4))
	{
		std::cout << "rsa1 generate error" << std::endl;
		goto end;
	}
/*
	rsa = RSA_generate_key(num, primes, 0, 0);
	if(rsa == NULL)
	{
		std::cout << "rsa error" << std::endl;
		goto end;
	}
*/	

    //if (!RSA_generate_multi_prime_key(rsa, num, primes, bn, cb))
	if (RSA_generate_multi_prime_key(rsa, 4096, 3, bn, cb) > 0)
	{
		std::cout << "rsa2 generate error" << std::endl;
		goto end;
	}

    RSA_get0_key(rsa, NULL, &e, NULL);
    hexe = BN_bn2hex(e);
    dece = BN_bn2dec(e);

	OPENSSL_free(hexe);
    OPENSSL_free(dece);
    cb_data.password = passout;
    cb_data.prompt_info = outfile;

/*
    if (!PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0,
                                     (pem_password_cb *)password_callback,
                                     &cb_data))
		std::cout << "PEM_write_bio_RSAPrivateKey error" << std::endl;
        goto end;
*/
	if(!PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL))
	{
		std::cout << "PEM_write_bio_RSAPrivateKey error" << std::endl;
        goto end;
	}
	ret = 0;

 end:

	std::cout << "2. error" << std::endl;
    BN_free(bn);
    BN_GENCB_free(cb);
    RSA_free(rsa);
    BIO_free_all(out);

	return ret;
}

int main()
{
	char* outfile = "/home/hskim/share/certificate-manager/build/private.key";
	genras(outfile);
	return 0;
}
