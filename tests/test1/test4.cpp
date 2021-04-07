#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <cstring>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define DEFBITS 2048
#define DEFPRIMES 2

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

#if defined(LOG_PRINT)
#define LOGE(x) std::cout << "ERROR : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGI(x) std::cout << "INFO : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGD(x) std::cout << "DEBUG : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#else
#define LOGE(x)
#define LOGI(x)
#define LOGD(x)
#endif

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

auto delPtrBIO = [](BIO *bio)
{
	BIO_free(bio);
	// BIO_free_all(bio);
	LOGD("called ..")
};

auto delPtrBN = [](BIGNUM *bn)
{
	BN_free(bn);
	LOGD("called ..")
};

auto delPtrRSA = [](RSA *rsa)
{
	RSA_free(rsa);
	LOGD("called ..")
};

auto delPtrEVP_PKEY = [](EVP_PKEY *evp)
{
	EVP_PKEY_free(evp);
	LOGD("called ..")
};

auto delPtrEVP_PKEY_CTX = [](EVP_PKEY_CTX *ctx)
{
	EVP_PKEY_CTX_free(ctx);
	LOGD("called ..")
};

auto delPtrEVP_MD_CTX = [](EVP_MD_CTX *ctx)
{
	EVP_MD_CTX_free(ctx);
	LOGD("called ..")
};

auto delPtrX509 = [](X509 *x509)
{
	X509_free(x509);
	LOGD("called ..")
};

auto delPtrX509_Name = [](X509_NAME *x509_name)
{
	X509_NAME_free(x509_name);
	LOGD("called ..")
};

using unique_ptr_bio_type_t				= std::unique_ptr<BIO, decltype(delPtrBIO)>;
using unique_ptr_bn_type_t 				= std::unique_ptr<BIGNUM, decltype(delPtrBN)>;
using unique_ptr_rsa_type_t 			= std::unique_ptr<RSA, decltype(delPtrRSA)>;
using unique_ptr_evp_pkey_type_t 		= std::unique_ptr<EVP_PKEY, decltype(delPtrEVP_PKEY)>;
using unique_ptr_evp_pkey_ctx_type_t 	= std::unique_ptr<EVP_PKEY_CTX, decltype(delPtrEVP_PKEY_CTX)>;
using unique_ptr_evp_md_ctx_type_t		= std::unique_ptr<EVP_MD_CTX, decltype(delPtrEVP_MD_CTX)>;
using unique_ptr_x509_type_t			= std::unique_ptr<X509, decltype(delPtrX509)>;
using unique_ptr_x509_name_type_t		= std::unique_ptr<X509_NAME, decltype(delPtrX509_Name)>;

enum class CRSAType
{
	TRADTIONAL_PEM,
	PKCS_PEM,
	PKCS8_PEM,
	ANS_DER
};

bool generate_rsa_key_files(const char *private_keyfile, const char *public_keyfile, int kBits, CRSAType type)
{
	int ret = 1;
	int primes = DEFPRIMES;

	if(private_keyfile == NULL)
	{
		LOGE("private key filename empty")
		return false;
	}

	if(public_keyfile == NULL)
	{
		LOGE("public key filename empty")
		return false;
	}

	unique_ptr_evp_pkey_ctx_type_t up_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), delPtrEVP_PKEY_CTX);
	ret = EVP_PKEY_keygen_init(up_evp_pkey_ctx.get());
	if(ret <= 0)
	{
		LOGE("Error setting RSA Init")
		return false;
	}

	ret = EVP_PKEY_CTX_set_rsa_keygen_bits(up_evp_pkey_ctx.get(), kBits);
	if(ret <= 0)
	{
		LOGE("Error setting RSA length")
		return false;
	}

	unique_ptr_bn_type_t up_bn(BN_new(), delPtrBN);
	ret = BN_set_word(up_bn.get(), RSA_F4);
	if(ret == 0)
	{
		LOGE("allocating RSA public exponent")
		return false;
	}

	ret = EVP_PKEY_CTX_set1_rsa_keygen_pubexp(up_evp_pkey_ctx.get(), up_bn.get());
	if(ret <= 0)
	{
		LOGE("setting RSA public exponent")
		return false;
	}

	ret = EVP_PKEY_CTX_set_rsa_keygen_primes(up_evp_pkey_ctx.get(), primes);
	if(ret <= 0)
	{
		LOGE("setting RSA public exponent")
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(EVP_PKEY_new(), delPtrEVP_PKEY);
	EVP_PKEY *tmp_evp_pkey = up_evp_pkey.get();
	ret = EVP_PKEY_keygen(up_evp_pkey_ctx.get(), &tmp_evp_pkey);
	if(ret == 0)
	{
		LOGE("generating RSA key")
		return false;
	}	

	unique_ptr_bio_type_t up_bio_private(BIO_new_file(private_keyfile, modestr('w', FORMAT_PEM)), delPtrBIO);
	// Generate Private Key
	switch(type)
	{
		case CRSAType::TRADTIONAL_PEM :
			ret = PEM_write_bio_PrivateKey_traditional(up_bio_private.get(), up_evp_pkey.get(), NULL, NULL, 0, NULL, NULL);
		break;
		case CRSAType::PKCS_PEM :
			ret = PEM_write_bio_PrivateKey(up_bio_private.get(), up_evp_pkey.get(), NULL, NULL, 0, NULL, NULL);
		break;
		//case CRSAType::PKCS8_PEM :
			// PEM_write_bio_PrivateKey is wrapper function of PEM_write_bio_PKCS8PrivateKey
		//	ret = PEM_write_bio_PKCS8PrivateKey(up_bio_private.get(), up_evp_pkey.get(), NULL, NULL, 0, NULL, NULL);
		//break;
		case CRSAType::ANS_DER :
			ret = i2d_PrivateKey_bio(up_bio_private.get(), up_evp_pkey.get());
		break;
	}

	if(ret == 0)
	{
		LOGE("private key file write")
		return false;
	}

	// Generate Public Key
	unique_ptr_bio_type_t up_bio_public(BIO_new_file(public_keyfile, "w"), delPtrBIO);
	switch(type)
	{
		case CRSAType::TRADTIONAL_PEM :
			ret = PEM_write_bio_PUBKEY(up_bio_public.get(), up_evp_pkey.get());
		break;
		case CRSAType::PKCS_PEM :
			ret = PEM_write_bio_PUBKEY(up_bio_public.get(), up_evp_pkey.get());
		break;
		//case CRSAType::PKCS8_PEM :
		//	ret = PEM_write_bio_RSAPublicKey(up_bio_public.get(), up_rsa.get());
		//	ret = PEM_write_bio_PUBKEY(up_bio_public.get(), up_evp_pkey.get());
		//break;
		case CRSAType::ANS_DER :
			ret = i2d_PUBKEY_bio(up_bio_public.get(), up_evp_pkey.get());
		break;
	}
 	
	if(ret == 0)
	{
		LOGE("public key file write")
		return false;
	}

	LOGI("Success ..")	
	return true;	
}

#if 0
bool rsa_encrypt(unsigned char *plain_text, size_t plain_len, unsigned char *cipher_text, size_t *cipher_len, const char *public_keyfile)
{
	int ret = 1;

	if(plain_text == NULL || cipher_text == NULL || cipher_len == NULL || public_keyfile == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	BIO *bio_key = BIO_new_file(public_keyfile, modestr('r', FORMAT_PEM));
	if(bio_key == NULL)
	{
		LOGE("can't open bio")
		return false;
	}

	EVP_PKEY *pkey = NULL;
	// format == FORMAT_PEM
	pkey = PEM_read_bio_PUBKEY(bio_key, NULL, NULL, NULL);
	if(pkey == NULL)
	{
		LOGE("can't load rsa public key")
		return false;
	}

	EVP_PKEY_CTX *ctx = NULL;
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if(ctx == NULL)
	{
		LOGE("can't open ctx new")
		return false;
	}

	ret = EVP_PKEY_encrypt_init(ctx);
    if(ret <= 0)
	{
		LOGE("can't encrypt init")
		return false;
    }

	ret = EVP_PKEY_CTX_set_rsa_padding(ctx, EVP_PADDING_PKCS7);
   	if(ret <= 0)
	{
		LOGE("can't set padding")
		return false;
    }

	ret = EVP_PKEY_encrypt(ctx, cipher_text, cipher_len, plain_text, plain_len);
   	if(ret <= 0)
	{
		LOGE("can't encrypt")
		return false;
    }

	return true;
}
#else
bool rsa_encrypt(unsigned char *plain_text, size_t plain_len, unsigned char *cipher_text, size_t *cipher_len, const char *public_keyfile)
{
	int ret = 1;

	if(plain_text == NULL || cipher_text == NULL || cipher_len == NULL || public_keyfile == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	unique_ptr_bio_type_t up_bio_key(BIO_new_file(public_keyfile, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_key.get() == NULL)
	{
		LOGE("can't open bio")
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PUBKEY(up_bio_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("can't load rsa public key")
		return false;
	}

	unique_ptr_evp_pkey_ctx_type_t up_evp_pkey_ctx(EVP_PKEY_CTX_new(up_evp_pkey.get(), NULL), delPtrEVP_PKEY_CTX);
	if(up_evp_pkey_ctx.get() == NULL)
	{
		LOGE("can't open ctx new")
		return false;
	}

	ret = EVP_PKEY_encrypt_init(up_evp_pkey_ctx.get());
    if(ret <= 0)
	{
		LOGE("can't encrypt init")
		return false;
    }

	ret = EVP_PKEY_CTX_set_rsa_padding(up_evp_pkey_ctx.get(), EVP_PADDING_PKCS7);
   	if(ret <= 0)
	{
		LOGE("can't set padding")
		return false;
    }

	ret = EVP_PKEY_encrypt(up_evp_pkey_ctx.get(), cipher_text, cipher_len, plain_text, plain_len);
   	if(ret <= 0)
	{
		LOGE("can't encrypt")
		return false;
    }

	return true;
}
#endif

//bool rsa_decrypt(unsigned char *cipher_text, size_t cipher_len, unsigned char *plain_text, size_t *plain_len, const char *private_keyfile, const char *passwd)
bool rsa_decrypt(unsigned char *cipher_text, size_t cipher_len, unsigned char *plain_text, size_t *plain_len, const char *private_keyfile)
{
	int ret = 1;
	size_t out_len = 0;

	if(cipher_text == NULL || plain_text == NULL || plain_len == NULL || private_keyfile == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	unique_ptr_bio_type_t up_bio_key(BIO_new_file(private_keyfile, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_key.get() == NULL)
	{
		LOGE("can't open bio")
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PrivateKey(up_bio_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("can't load rsa private key")
		return false;
	}

	unique_ptr_evp_pkey_ctx_type_t up_evp_pkey_ctx(EVP_PKEY_CTX_new(up_evp_pkey.get(), NULL), delPtrEVP_PKEY_CTX);
	if(up_evp_pkey_ctx.get() == NULL)
	{
		LOGE("can't open ctx new")
		return false;
	}

	ret = EVP_PKEY_decrypt_init(up_evp_pkey_ctx.get());
    if(ret <= 0)
	{
		LOGE("can't decrypt init")
		return false;
    }

	ret = EVP_PKEY_CTX_set_rsa_padding(up_evp_pkey_ctx.get(), EVP_PADDING_PKCS7);
   	if(ret <= 0)
	{
		LOGE("can't set padding")
		return false;
    }

	ret = EVP_PKEY_decrypt(up_evp_pkey_ctx.get(), NULL, &out_len, cipher_text, cipher_len);
   	if(ret <= 0)
	{
		LOGE("can't get decrypt buffer length")
		return false;
    }

	std::cout << "outlen : " << out_len << std::endl;
	*plain_len = out_len;

	ret = EVP_PKEY_decrypt(up_evp_pkey_ctx.get(), plain_text, plain_len, cipher_text, cipher_len);
   	if(ret <= 0)
	{
		LOGE("can't get decrypt buffer length")
		return false;
    }

	return true;	
}

//int rsa_sign(unsigned char *sign_text, size_t sign_len, unsigned char *result, size_t *result_len, const unsigned char *privatekey_file, const unsigned char *passwd)
bool rsa_sign(unsigned char *input_text, size_t input_text_len, unsigned char *signed_text, size_t *signed_len, const char *privatekey_file)
{
	int ret = 1;

	if(input_text == NULL || signed_text == NULL || signed_len == NULL || privatekey_file == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	unique_ptr_bio_type_t up_bio_key(BIO_new_file(privatekey_file, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_key.get() == NULL)
	{
		LOGE("can't open bio")
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PrivateKey(up_bio_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("can't load rsa private key")
		return false;
	}

	unique_ptr_evp_md_ctx_type_t up_evp_md_ctx(EVP_MD_CTX_new(), delPtrEVP_MD_CTX);
	if(up_evp_md_ctx.get() == NULL)
	{
		LOGE("can't allocate evp md ctx")
		return false;
	}

	ret = EVP_MD_CTX_init(up_evp_md_ctx.get());
	if(ret != 1)
	{
		LOGE("EVP_MD_CTX_init")
		return false;
	}

	// need to change optionally hash function
	ret = EVP_SignInit_ex(up_evp_md_ctx.get(), EVP_sha256(), NULL);
	if(ret != 1)
	{
		LOGE("EVP_SignInit_ex")
		return false;
	}

    ret = EVP_SignUpdate(up_evp_md_ctx.get(), input_text, input_text_len);
    if (ret != 1) 
	{
		LOGE("EVP_SignUpdate")
		return false;
    }

    ret = EVP_SignFinal(up_evp_md_ctx.get(), signed_text, (unsigned int*)signed_len, up_evp_pkey.get());
    if (ret != 1) 
	{
		LOGE("EVP_SignUpdate")
		return false;
    }

	return true;
}

bool rsa_verify(unsigned char *signed_text, size_t signed_len, unsigned char *result, size_t result_len, const char *publickey_file)
{
	int ret = 1;

	if(signed_text == NULL || result == NULL || publickey_file == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	unique_ptr_bio_type_t up_bio_key(BIO_new_file(publickey_file, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_key.get() == NULL)
	{
		LOGE("can't open bio")
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PUBKEY(up_bio_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("can't load rsa public key")
		return false;
	}

	unique_ptr_evp_md_ctx_type_t up_evp_md_ctx(EVP_MD_CTX_new(), delPtrEVP_MD_CTX);
	if(up_evp_md_ctx.get() == NULL)
	{
		LOGE("can't allocate evp md ctx")
		return false;
	}

	ret = EVP_MD_CTX_init(up_evp_md_ctx.get());
	if(ret != 1)
	{
		LOGE("EVP_MD_CTX_init")
		return false;
	}

    ret = EVP_VerifyInit_ex(up_evp_md_ctx.get(), EVP_sha256(), NULL);
    if (ret != 1) 
	{
		LOGE("EVP_VerifyInit_ex")
		return false;
    }

    ret = EVP_VerifyUpdate(up_evp_md_ctx.get(), result, result_len);
    if (ret != 1) 
	{
		LOGE("EVP_VerifyUpdate")
		return false;
    }

    ret = EVP_VerifyFinal(up_evp_md_ctx.get(), signed_text, (unsigned int)signed_len, up_evp_pkey.get());
    if (ret != 1)
	{
		LOGE("EVP_VerifyFinal")
		return false;
    }

	return true;
}

bool generate_x509_certificate(const char *certificate_filename, const char *ca_privatekey_name, long days)
{
	int ret = 1;

	if(certificate_filename == NULL || ca_privatekey_name == NULL)
	{
		LOGE("wrong input parameter")
		return false;
	}

	unique_ptr_bio_type_t up_bio_cert(BIO_new_file(certificate_filename, modestr('w', FORMAT_PEM)), delPtrBIO);
	if(up_bio_cert.get() == NULL)
	{
		LOGE("can't open bio")
		return false;
	}

	unique_ptr_bio_type_t up_bio_key(BIO_new_file(ca_privatekey_name, modestr('r', FORMAT_PEM)), delPtrBIO);
	if(up_bio_key.get() == NULL)
	{
		LOGE("can't open bio")
		return false;
	}

	unique_ptr_evp_pkey_type_t up_evp_pkey(PEM_read_bio_PrivateKey(up_bio_key.get(), NULL, NULL, NULL), delPtrEVP_PKEY);
	if(up_evp_pkey.get() == NULL)
	{
		LOGE("can't load rsa private key")
		return false;
	}

	unique_ptr_x509_type_t up_x509(X509_new(), delPtrX509);
	if(up_x509.get() == NULL)
	{
		LOGE("can't load x509")
		return false;
	}

	ret = X509_set_pubkey(up_x509.get(), up_evp_pkey.get());
	if(ret == 0)
	{
		LOGE("X509_set_pubkey")
		return false;
	}

	unique_ptr_x509_name_type_t up_x509_name(X509_get_subject_name(up_x509.get()), delPtrX509_Name);
	if(up_x509_name.get() == NULL)
	{
		LOGE("can't load up_x509_name")
		return false;
	}

	// 여기는 더 봐야 할 부분
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

	const uchar country[] = "KR";
	const uchar company[] = "LGE Inc";
	const uchar common_name[] = "localhost";

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "C", MBSTRING_ASC, country, -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt")
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "O", MBSTRING_ASC, company, -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt")
		return false;
	}

	ret = X509_NAME_add_entry_by_txt(up_x509_name.get(), "C", MBSTRING_ASC, common_name, -1, -1, 0);
	if(ret == 0)
	{
		LOGE("X509_NAME_add_entry_by_txt")
		return false;
	}		

	ret = X509_set_issuer_name(up_x509.get(), up_x509_name.get());
	if(ret == 0)
	{
		LOGE("X509_set_issuer_name")
		return false;
	}

    // https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl
	ret = X509_sign(up_x509.get(), up_evp_pkey.get(), EVP_sha256());
	if(ret == 0)
	{
		LOGE("X509_sign")
		return false;
	}

	ret = PEM_write_bio_X509(up_bio_cert.get(), up_x509.get());
	if(ret == 0)
	{
		LOGE("PEM_write_bio_X509")
		return false;
	}

	return true;
}

void test_generate_rsa_key_files()
{
	std::vector<int> kBits {1024, 2048, 4096};

	for( auto kbits : kBits)
	{
		std::string privateFileName = "privateKey-";
		std::string publicFileName = "publickey-";
		std::stringstream sint;
		sint << kbits;

		privateFileName = privateFileName + sint.str() + ".pem";
		publicFileName = publicFileName + sint.str() + ".pem";

		generate_rsa_key_files(privateFileName.c_str(), publicFileName.c_str(), kbits, CRSAType::PKCS_PEM);
	}
}

void test_rsa_encrypt_decrypt()
{
#if 0	
	bool ret = false;
	size_t cipher_len = 0;
	size_t derypted_len = 0;

	//std::string plain_text("heesoon.kim test about test_rsa_encrypt");
	std::string plain_text("11111");
	std::string cipher_text(plain_text.size(), 'X');
	std::string decrypted_text(plain_text.size()+100, 'X');

	ret = rsa_encrypt((unsigned char*)plain_text.c_str(), plain_text.size(), (unsigned char*)cipher_text.c_str(), &cipher_len, "publickey-2048.pem");

	if(ret == true)
	{
		ret = rsa_decrypt((unsigned char*)cipher_text.c_str(), cipher_text.size(), (unsigned char*)decrypted_text.c_str(), &derypted_len, "privateKey-2048.pem");
		if(ret == true)
		{
			std::cout << decrypted_text << std::endl;
		}
	}
#else
	bool ret = false;
	unsigned char cipher_text[1024];
	unsigned char plain_text[] = "heesoon.kim rsa test";
	size_t plain_len = std::strlen((char*)plain_text);
	size_t cipher_len = 1024;

	ret = rsa_encrypt(plain_text, plain_len, cipher_text, &cipher_len, "publickey-2048.pem");
	if(ret == true)
	{
		std::cout << "cipher length : " << cipher_len << std::endl;
	}

	for(int i = 0; i < cipher_len; i++)
	{
		std::printf("%02X", cipher_text[i]);
	}
	std::cout << std::endl;

	std::memset(plain_text, '\0', plain_len);
	plain_len = 1;

	ret = rsa_decrypt(cipher_text, cipher_len, plain_text, &plain_len, "privateKey-2048.pem");
	if(ret == true)
	{
		std::cout << "decrypted length : " << plain_len << std::endl;
	}

	std::cout << plain_text << std::endl;
#endif	
}

void test_sign_verify()
{
	bool ret = false;
	unsigned char result[1024];
	unsigned char input_text[] = "heesoon.kim sign test";
	size_t result_len = 256;
	size_t input_text_len = std::strlen((char*)input_text);

	ret = rsa_sign(input_text, input_text_len, result, &result_len, "privateKey-2048.pem");
	if(ret == false)
	{
		LOGE("rsa_sign")
		return;
	}

	for(int i = 0; i < result_len; i++)
	{
		std::printf("%02X", result[i]);
	}
	std::cout << std::endl;

	ret = rsa_verify(result, result_len, input_text, input_text_len, "publickey-2048.pem");
	if(ret == false)
	{
		LOGE("rsa_verify")
		return;
	}

	LOGI("Succee in test_sign_verify")
}

int main()
{
	test_generate_rsa_key_files();
	test_rsa_encrypt_decrypt();
	test_sign_verify();
	return 0;
}