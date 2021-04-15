#include <iostream>
#include <openssl/rsa.h>
#include <openssl/x509.h>
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

typedef struct st_subject
{
	char *commonName;
	char *countryName;
	char *stateOrProvinceName;
	char *localityName;
	char *organizationName;
	char *emailAddress;
} subject_t;

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

bool generate_csr(const char *config_filename, const char *req_filename, const char *privatekey_file, subject_t *subject)
{
	int ret = 0;
	CONF *conf = NULL;
	X509_REQ *req = NULL;
	X509_NAME *subject = NULL;
	const EVP_MD *evp_md;

	conf = load_config(config_filename);
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

	// load signing algorithm
	char *md = NCONF_get_string(conf, section, "default_md");
	if(p == NULL)
	{
		std::cout << "error in default_md" << std::endl;
		return 1;
	}
	std::cout << "default_md : " << md << std::endl;

	//load private key
	EVP_PKEY *pkey = NULL;
	BIO *bio = BIO_new_file(privatekey_file, modestr('r', FORMAT_PEM));
	if(bio == NULL)
	{
		std::cout << "error in BIO_new_file" << std::endl;
		return 1;
	}

	BIO *bio_out = BIO_new_file(req_filename, modestr('w', FORMAT_PEM));
	if(bio_out == NULL)
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

	ret = X509_REQ_set_version(req, 0L); /*version 1 */
	if(ret == 0)
	{
		std::cout << "error in X509_REQ_set_version" << std::endl;
		return 1;		
	}

	// create a certificate request
	req = X509_REQ_new();

	// set certificate request 'Subject:'
	x509_subject = X509_NAME_new();

	X509_NAME_add_entry_by_txt(x509_subject, "commonName", MBSTRING_ASC, (unsigned char*)subject->commonName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(x509_subject, "countryName", MBSTRING_ASC, (unsigned char*)subject->countryName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(x509_subject, "stateOrProvinceName", MBSTRING_ASC, (unsigned char*)subject->stateOrProvinceName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(x509_subject, "localityName", MBSTRING_ASC, (unsigned char*)subject->localityName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(x509_subject, "emailAddress", MBSTRING_ASC, (unsigned char*)subject->emailAddress, -1, -1, 0);
	X509_NAME_add_entry_by_txt(x509_subject, "organizationName", MBSTRING_ASC, (unsigned char*)subject->organizationName, -1, -1, 0);

	X509_REQ_set_subject_name(req, subject);
	X509_NAME_free(subject);

	// set certificate request public key
	X509_REQ_set_pubkey(req, keyring);

	// create a message digest
	evp_md = EVP_get_digestbyname(md);
	if(evp_md == NULL)
	{
		return false;
	}

	// sign certificate request
	X509_REQ_sign(req, pkey, evp_md);

	// verify
	EVP_PKEY *tpubkey = pkey;
	if(pkey == NULL)
	{
		tpubkey = X509_REQ_get0_pubkey(req);
		if(tpubkey == NULL)
		{
			return false;
		}
	}

	ret = X509_REQ_verify(req, tpubkey);
	if(i <= 0)
	{
		return false;
	}

	ret = PEM_write_bio_X509_REQ(bio_out, req);
	if(ret == 0)
	{
		return false;
	}

	return true;
}

void test_generate_csr()
{

}

int main()
{
	test_generate_csr();
	return 0;
}