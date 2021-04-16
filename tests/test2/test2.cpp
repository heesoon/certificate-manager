#include <iostream>
#include <string>
#include <cstring>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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

#define BASE_SECTION            "ca"

#define ENV_DEFAULT_CA          "default_ca"

#define STRING_MASK             "string_mask"
#define UTF8_IN                 "utf8"

#define ENV_NEW_CERTS_DIR       "new_certs_dir"
#define ENV_CERTIFICATE         "certificate"
#define ENV_SERIAL              "serial"
#define ENV_RAND_SERIAL         "rand_serial"
#define ENV_CRLNUMBER           "crlnumber"
#define ENV_PRIVATE_KEY         "private_key"
#define ENV_DEFAULT_DAYS        "default_days"
#define ENV_DEFAULT_STARTDATE   "default_startdate"
#define ENV_DEFAULT_ENDDATE     "default_enddate"
#define ENV_DEFAULT_CRL_DAYS    "default_crl_days"
#define ENV_DEFAULT_CRL_HOURS   "default_crl_hours"
#define ENV_DEFAULT_MD          "default_md"
#define ENV_DEFAULT_EMAIL_DN    "email_in_dn"
#define ENV_PRESERVE            "preserve"
#define ENV_POLICY              "policy"
#define ENV_EXTENSIONS          "x509_extensions"
#define ENV_CRLEXT              "crl_extensions"
#define ENV_MSIE_HACK           "msie_hack"
#define ENV_NAMEOPT             "name_opt"
#define ENV_CERTOPT             "cert_opt"
#define ENV_EXTCOPY             "copy_extensions"
#define ENV_UNIQUE_SUBJECT      "unique_subject"
#define ENV_DATABASE            "database"

# define SERIAL_RAND_BITS        159

#if defined(LOG_PRINT)
#define LOGE(x) std::cout << "ERROR : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGI(x) std::cout << "INFO : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGD(x) std::cout << "DEBUG : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#else
#define LOGE(x)
#define LOGI(x)
#define LOGD(x)
#endif

auto delPtrBN = [](BIGNUM *bn)
{
	if(bn != NULL)
		BN_free(bn);
	LOGD("called ..")
};

auto delPtrBIO = [](BIO *bio)
{
	if(bio != NULL)
		BIO_free(bio);
	// BIO_free_all(bio);
	LOGD("called ..")
};

auto delPtrCONF = [](CONF *conf)
{
	if(conf != NULL)
		NCONF_free(conf);
	LOGD("called ..")
};

auto delPtrX509_REQ = [](X509_REQ *x509_req)
{
	if(x509_req != NULL)
		X509_REQ_free(x509_req);
	LOGD("called ..")
};

auto delPtrX509_NAME = [](X509_NAME *x509_name)
{
	if(x509_name != NULL)
		X509_NAME_free(x509_name);
	LOGD("called ..")
};

auto delPtrEVP_PKEY = [](EVP_PKEY *evp)
{
	if(evp != NULL)
		EVP_PKEY_free(evp);
	LOGD("called ..")
};

auto delPtrX509 = [](X509 *x509)
{
	if(x509 != NULL)
		X509_free(x509);
	LOGD("called ..")
};

using unique_ptr_bn_type_t 				= std::unique_ptr<BIGNUM, decltype(delPtrBN)>;
using unique_ptr_bio_type_t				= std::unique_ptr<BIO, decltype(delPtrBIO)>;
using unique_ptr_conf_type_t			= std::unique_ptr<CONF, decltype(delPtrCONF)>;
using unique_ptr_x509_req_type_t		= std::unique_ptr<X509_REQ, decltype(delPtrX509_REQ)>;
using unique_ptr_x509_name_type_t		= std::unique_ptr<X509_NAME, decltype(delPtrX509_NAME)>;
using unique_ptr_evp_pkey_type_t 		= std::unique_ptr<EVP_PKEY, decltype(delPtrEVP_PKEY)>;
using unique_ptr_x509_type_t			= std::unique_ptr<X509, decltype(delPtrX509)>;

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

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;

    btmp = b == NULL ? BN_new() : b;
    if (btmp == NULL)
        return 0;

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

 error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}

BIGNUM *load_serial(const char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if (ai == NULL)
        goto err;

    in = BIO_new_file(serialfile, "r");
    if (in == NULL) {
        if (!create) {
            perror(serialfile);
            goto err;
        }
        //ERR_clear_error();
        ret = BN_new();
        if (ret == NULL || !rand_serial(ret, ai))
            //BIO_printf(bio_err, "Out of memory\n");
			std::cout << "Out of memory" << std::endl;
    } 
	else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            //BIO_printf(bio_err, "Unable to load number from %s\n",
            //           serialfile);
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            //BIO_printf(bio_err, "Error converting number from bin to BIGNUM\n");
            goto err;
        }
    }

    if (ret && retai) {
        *retai = ai;
        ai = NULL;
    }
 err:
    //ERR_print_errors(bio_err);
    BIO_free(in);
    ASN1_INTEGER_free(ai);
    return ret;
}


bool ca(const char *input_config_filename, const char *input_csr_filename, const char *output_certificate_filename)
{
	int ret = 0;
	long errorline = -1;
	char *pChar = NULL;
	char *ca_privatekey_file = NULL;
	char *ca_certificate_file = NULL;
	char *md_name = NULL;
	char *policy = NULL;
	const char *serialfile = NULL;
	char *extensions = NULL;
	const EVP_MD *evp_md;
	unsigned long chtype = MBSTRING_ASC;
	long days = 0;
	int email_dn = 0;
	EVP_PKEY *pktmp = NULL;
	STACK_OF(CONF_VALUE) *attribs = NULL;

	if(input_config_filename == NULL || input_csr_filename == NULL || output_certificate_filename == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	// 1. load configuration file. some information is gotten from configuration file
	unique_ptr_bio_type_t up_bio_input_config(BIO_new_file(input_config_filename, modestr('r', FORMAT_TEXT)), delPtrBIO);
	if(up_bio_input_config.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_conf_type_t up_config(NCONF_new(NULL), delPtrCONF);
	if(up_config.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	ret = NCONF_load_bio(up_config.get(), up_bio_input_config.get(), &errorline);
	if(ret == 0)
	{
		LOGE("NCONF_load_bio");
		return false;
	}

	ret = CONF_modules_load(up_config.get(), NULL, 0);
	if(ret <= 0)
	{
		LOGE("CONF_modules_load");
		return false;
	}

	// load signing algorithm from configuration file
	pChar = NCONF_get_string(up_config.get(), BASE_SECTION, STRING_MASK);
	if(pChar == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	ret = ASN1_STRING_set_default_mask_asc(pChar);
	if(ret == 0)
	{
		LOGE("ASN1_STRING_set_default_mask_asc");
		return false;
	}

	if(chtype != MBSTRING_UTF8)
	{
		pChar = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, UTF8_IN);
		if(pChar == NULL)
		{
			LOGE("NCONF_get_string");
			return false;
		}
		else if(std::strcmp(pChar, "yes") == 0)
		{
			chtype = MBSTRING_UTF8;
		}
	}

    // Getting CA Privatek key filename from configuration //
	ca_privatekey_file = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_PRIVATE_KEY);
	if(ca_privatekey_file == NULL)
	{
		LOGE("ca_privatekey_file");
		return false;
	}

	// read ca private key
	unique_ptr_bio_type_t up_bio_input_ca_private_key(BIO_new_file(ca_privatekey_file, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_input_ca_private_key.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PrivateKey(up_bio_input_ca_private_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("PEM_read_bio_PrivateKey");
		return false;
	}

	// Getting CA certificate filename from configuration //
	ca_certificate_file = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_CERTIFICATE);
	if(ca_certificate_file == NULL)
	{
		LOGE("ca_certificate_file");
		return false;
	}

	// read ca private key
	unique_ptr_bio_type_t up_bio_input_ca_certificate(BIO_new_file(ca_certificate_file, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_input_ca_certificate.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_x509_type_t up_x509(PEM_read_bio_X509_AUX(up_bio_input_ca_private_key.get(), NULL, NULL, NULL), delPtrX509);
	if(up_x509.get() == NULL)
	{
		LOGE("PEM_read_bio_X509_AUX");
		return false;
	}

	// just skip ENV_PRESERVE, ENV_MSIE_HACK, ENV_NAMEOPT, ENV_CERTOPT
	// TO DO

	serialfile = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_SERIAL);
	if(serialfile == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	unique_ptr_bn_type_t up_bn_serial(load_serial(serialfile, 0, NULL), delPtrBN);
	if(up_bn_serial.get() == NULL)
	{
		LOGE("load_serial");
		return false;
	}	

	// load signing algorithm from configuration file
	md_name = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_DEFAULT_MD);
	if(md_name == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	// 4. apply signing
	evp_md = EVP_get_digestbyname(md_name);
	if(evp_md == NULL)
	{
		LOGE("EVP_get_digestbyname");
		return false;		
	}

	// load signing algorithm from configuration file
	policy = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_POLICY);
	if(policy == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	extensions = NCONF_get_string(up_config.get(), ENV_DEFAULT_CA, ENV_EXTENSIONS);
	if(extensions == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	X509V3_CTX ctx;
	X509V3_set_ctx_test(&ctx);
	X509V3_set_nconf(&ctx, up_config.get());

	ret = X509V3_EXT_add_nconf(up_config.get(), &ctx, extensions, NULL);
	if(ret == 0)
	{
		LOGE("X509V3_EXT_add_nconf");
		return false;		
	}

	ret = NCONF_get_number(up_config.get(), ENV_DEFAULT_CA, ENV_DEFAULT_DAYS, &days);
	if(ret == 0)
	{
		LOGE("NCONF_get_number");
		return false;		
	}

	attribs = NCONF_get_section(up_config.get(), policy);
	if(attribs == NULL)
	{
		LOGE("NCONF_get_section");
		return false;
	}

	// read csr
	unique_ptr_bio_type_t up_bio_input_csr(BIO_new_file(input_csr_filename, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_input_csr.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_x509_req_type_t up_x509_req(PEM_read_bio_X509_REQ(up_bio_input_csr.get(), NULL, NULL, NULL), delPtrX509_REQ);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("PEM_read_bio_X509_REQ");
		return false;
	}

	pktmp = X509_REQ_get0_pubkey(up_x509_req.get());
	if(pktmp == NULL)
	{
		LOGE("X509_REQ_get0_pubkey");
		return false;
	}

	LOGI("Success")
	return true;
}

void test_ca()
{
	bool ret = false;
	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::string input_csr_filename = "csr.pem";
	std::string output_certificate_filename = "customer_certificate.pem";

	ret = ca(static_cast<const char*>(input_config_filename.c_str()), static_cast<const char*>(input_csr_filename.c_str()), static_cast<const char*>(output_certificate_filename.c_str()));
	if(ret == false)
	{
		LOGE("ca")
		return;
	}

	LOGI("Success")	
}

int main()
{
	test_ca();
	return 0;
}