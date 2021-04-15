#include <iostream>
#include <string>
#include <memory>
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

#if defined(LOG_PRINT)
#define LOGE(x) std::cout << "ERROR : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGI(x) std::cout << "INFO : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGD(x) std::cout << "DEBUG : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#else
#define LOGE(x)
#define LOGI(x)
#define LOGD(x)
#endif

typedef struct st_subject
{
	char *commonName;
	char *countryName;
	char *stateOrProvinceName;
	char *localityName;
	char *organizationName;
	char *emailAddress;
} subject_t;

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

using unique_ptr_bio_type_t				= std::unique_ptr<BIO, decltype(delPtrBIO)>;
using unique_ptr_conf_type_t			= std::unique_ptr<CONF, decltype(delPtrCONF)>;
using unique_ptr_x509_req_type_t		= std::unique_ptr<X509_REQ, decltype(delPtrX509_REQ)>;
using unique_ptr_x509_name_type_t		= std::unique_ptr<X509_NAME, decltype(delPtrX509_NAME)>;
using unique_ptr_evp_pkey_type_t 		= std::unique_ptr<EVP_PKEY, decltype(delPtrEVP_PKEY)>;

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

#if 0
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
#endif

bool generate_csr(const char *input_config_filename, const char *input_key_filename, subject_t *subject, const char *output_csr_filename)
{
	int ret = 0;
	long errorline = -1;
	char *md_name = NULL;
	const char *section = "req";
	const EVP_MD *evp_md;

	if(input_config_filename == NULL || input_key_filename == NULL || subject == NULL || output_csr_filename == NULL)
	{
		//LOGE("wrong input parameter")
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
	if(ret > 0)
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
	md_name = NCONF_get_string(up_config.get(), section, "default_md");
	if(md_name == NULL)
	{
		LOGE("NCONF_get_string");
		return false;
	}

	// TO DO. if need to add more value from configuration file, add code here by using NCONF_get_string

	// 2. setting subjects
	unique_ptr_x509_name_type_t up_x509_name(X509_NAME_new(), delPtrX509_NAME);
	if(up_x509_name.get() == NULL)
	{
		LOGE("X509_NAME_new");
		return false;
	}

	//ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "commonName", MBSTRING_ASC, (unsigned char*)subject->commonName, -1, -1, 0);
	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "commonName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->commonName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "countryName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->countryName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "stateOrProvinceName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->stateOrProvinceName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "localityName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->localityName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "organizationName", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->organizationName), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "emailAddress", MBSTRING_ASC, reinterpret_cast<unsigned char*>(subject->emailAddress), -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt");
		return false;
	}
	
	// 3. setting req
	unique_ptr_x509_req_type_t up_x509_req(X509_REQ_new(), delPtrX509_REQ);
	if(up_x509_req.get() == NULL)
	{
		LOGE("X509_REQ_new");
		return false;
	}

	// setting req revsion. currently there is only version 1
	ret = X509_REQ_set_version(up_x509_req.get(), 0L);
	if(ret == 0)
	{
		LOGE("X509_REQ_set_version");
		return false;
	}

	// setting subject to req
	ret = X509_REQ_set_subject_name(up_x509_req.get(), up_x509_name.get());
	if(ret == 0)
	{
		LOGE("X509_REQ_set_subject_name");
		return false;
	}

	// setting public key information to req
	unique_ptr_bio_type_t up_bio_input_key(BIO_new_file(input_key_filename, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_input_key.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PrivateKey(up_bio_input_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("PEM_read_bio_PrivateKey");
		return false;
	}

	ret = X509_REQ_set_pubkey(up_x509_req.get(), up_evp_pkey.get());
	if(ret == 0)
	{
		LOGE("X509_REQ_set_pubkey");
		return false;
	}

	// 4. apply signing
	evp_md = EVP_get_digestbyname(md_name);
	if(evp_md == NULL)
	{
		LOGE("EVP_get_digestbyname");
		return false;		
	}

	ret = X509_REQ_sign(up_x509_req.get(), up_evp_pkey.get(), evp_md);
	if(ret == 0)
	{
		LOGE("X509_REQ_sign");
		return false;
	}

	// 5. req verify
	EVP_PKEY *tpubkey = up_evp_pkey.get();
	if(tpubkey == NULL)
	{
		tpubkey = X509_REQ_get0_pubkey(up_x509_req.get());
		if(tpubkey == NULL)
		{
			LOGE("X509_REQ_get0_pubkey");
			return false;
		}
	}

	ret = X509_REQ_verify(up_x509_req.get(), tpubkey);
	if(ret <= 0)
	{
		LOGE("X509_REQ_verify");
		return false;
	}

	// 5. generate csr output file
	unique_ptr_bio_type_t up_bio_out_csr(BIO_new_file(output_csr_filename, modestr('w', FORMAT_PEM)), delPtrBIO);
	if(up_bio_out_csr.get() == NULL)
	{
		LOGE("BIO_new_file");
		return false;
	}

	ret = PEM_write_bio_X509_REQ(up_bio_out_csr.get(), up_x509_req.get());
	if(ret == 0)
	{
		LOGE("PEM_write_bio_X509_REQ");
		return false;
	}

	LOGI("Success")
	return true;
}

void test_generate_csr()
{
	bool ret = false;

	std::string input_config_filename = "/home/hskim/share/certificate-manager/tests/test3/scripts/customer_openssl.cnf";
	std::string input_privatekey_filename = "test_privatekey.pem";
	std::string output_csr_filename = "csr.pem";

	std::unique_ptr<subject_t> up_sub(new subject_t);
	up_sub.get()->commonName = "Customer Inc";
	up_sub.get()->countryName = "KR";
	up_sub.get()->stateOrProvinceName = "Seoul";
	up_sub.get()->localityName = "Seoul";
	up_sub.get()->organizationName = "Customer Inc R&D";
	up_sub.get()->emailAddress = "customer@rnd.com";

	ret = generate_csr(static_cast<const char*>(input_config_filename.c_str()), static_cast<const char*>(input_privatekey_filename.c_str()), up_sub.get(), static_cast<const char*>(output_csr_filename.c_str()));
	if(ret == false)
	{
		LOGE("generate_csr")
		return;
	}

	LOGI("success")
}

int main()
{
	test_generate_csr();
	return 0;
}