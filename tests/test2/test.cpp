#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/conf.h>

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
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPublicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPublicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */

#define BITS               "default_bits"
#define KEYFILE            "default_keyfile"
#define PROMPT             "prompt"
#define DISTINGUISHED_NAME "distinguished_name"
#define ATTRIBUTES         "attributes"
#define V3_EXTENSIONS      "x509_extensions"
#define REQ_EXTENSIONS     "req_extensions"
#define STRING_MASK        "string_mask"
#define UTF8_IN            "utf8"
#define BITS               "default_bits"
#define KEYFILE            "default_keyfile"
#define PROMPT             "prompt"
#define DISTINGUISHED_NAME "distinguished_name"
#define ATTRIBUTES         "attributes"
#define V3_EXTENSIONS      "x509_extensions"
#define REQ_EXTENSIONS     "req_extensions"
#define STRING_MASK        "string_mask"
#define UTF8_IN            "utf8"

int FMT_istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

static const char *modestr(char mode, int format)
{
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return FMT_istext(format) ? "a" : "ab";
    case 'r':
        return FMT_istext(format) ? "r" : "rb";
    case 'w':
        return FMT_istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

CONF* load_config(const char *filename)
{
	long errorline = -1;
	int i;
	BIO *in = NULL;
	CONF *conf;

	in = BIO_new_file(filename, modestr('r', FORMAT_TEXT));
	if(in == NULL)
	{
		std::cout << "error in BIO_new_file" << std::endl;
		return NULL;
	}

	conf = NCONF_new(NULL);
	i = NCONF_load_bio(conf, in, &errorline);
	if(i > 0)
	{
		std::cout << "success in NCONF_load_bio" << std::endl;
		BIO_free(in);
		return conf;
	}
	
	std::cout << "error in NCONF_load_bio" << std::endl;

	BIO_free(in);
	NCONF_free(conf);
}

int main()
{
	int ret = 0;
	CONF *conf = NULL;
	const char *section = "req";
	long newkey_len = -1;

	conf = load_config("/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf");
	if(conf == NULL)
	{
		std::cout << "error in load_config" << std::endl;
		NCONF_free(conf);
		return 1;
	}

	ret = CONF_modules_load(conf, NULL, 0);
	if(ret <= 0)
	{
		std::cout << "error in CONF_modules_load" << std::endl;
		NCONF_free(conf);
		return 1;
	}

	ret = NCONF_get_number(conf, section, BITS, &newkey_len);
	if(ret == 0)
	{
		std::cout << "error in NCONF_get_number" << std::endl;
		//newkey_len = DEFAULT_KEY_LENGTH;
		newkey_len = 2048;
		return 1;
	}

	std::cout << "newkey_len : " << newkey_len << std::endl;

	char *p = NCONF_get_string(conf, section, "default_md");
	if(p == NULL)
	{
		std::cout << "error in default_md" << std::endl;
		return 1;
	}

	std::cout << "default_md : " << p << std::endl;

	char *extensions = NCONF_get_string(conf, section, V3_EXTENSIONS);
	if(extensions == NULL)
	{
		std::cout << "error in V3_EXTENSIONS" << std::endl;
		return 1;
	}
	std::cout << "V3_EXTENSIONS : " << extensions << std::endl;

	NCONF_free(conf);

	//load private key
	EVP_PKEY *pkey = NULL;
	BIO *bio = BIO_new_file("privatekey.pem", modestr('r', FORMAT_PEM));
	if(bio == NULL)
	{
		std::cout << "error in BIO_new_file" << std::endl;
		return 1;
	}

	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if(pkey == NULL)
	{
		std::cout << "error in PEM_read_bio_PrivateKey" << std::endl;
		return 1;
	}

	// make request
	X509_REQ *req = NULL;
	req = X509_REQ_new();
	if(req == NULL)
	{
		std::cout << "error in X509_REQ_new" << std::endl;
		return 1;
	}

	ret = X509_REQ_set_version(req, 0L); /*version 1 */
	if(ret == 0)
	{
		std::cout << "error in X509_REQ_set_version" << std::endl;
		return 1;		
	}

	X509_NAME *n;
	ret = X509_REQ_set_subject_name(req, n); /*version 1 */
	if(ret == 0)
	{
		std::cout << "error in X509_REQ_set_subject_name" << std::endl;
		X509_NAME_free(n);
		return 1;		
	}	

	return 0;
}