#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define DEFBITS 2048
#define DEFPRIMES 2

#if defined(LOG_PRINT)
#define LOGE(x) std::cout << "ERROR : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGI(x) std::cout << "INFO : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#define LOGD(x) std::cout << "DEBUG : " << "[" << __FILE__ << ", " << __FUNCTION__ << ", " << __LINE__ << "] " << x << std::endl;
#else
#define LOGE(x)
#define LOGI(x)
#define LOGD(x)
#endif

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

using unique_ptr_bio_type_t				= std::unique_ptr<BIO, decltype(delPtrBIO)>;
using unique_ptr_bn_type_t 				= std::unique_ptr<BIGNUM, decltype(delPtrBN)>;
using unique_ptr_rsa_type_t 			= std::unique_ptr<RSA, decltype(delPtrRSA)>;
using unique_ptr_evp_pkey_type_t 		= std::unique_ptr<EVP_PKEY, decltype(delPtrEVP_PKEY)>;
using unique_ptr_evp_pkey_ctx_type_t 	= std::unique_ptr<EVP_PKEY_CTX, decltype(delPtrEVP_PKEY_CTX)>;

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

	unique_ptr_bio_type_t up_bio_private(BIO_new_file(private_keyfile, "w"), delPtrBIO);
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

void test_generate_rsa_key_files()
{
	std::vector<int> kBits {1024, 2048, 4096};

	for( auto kbits : kBits)
	{
		std::string privateFileName = "privateKey-";
		std::string publicFileName = "public-";
		std::stringstream sint;
		sint << kbits;

		privateFileName = privateFileName + sint.str() + ".pem";
		publicFileName = publicFileName + sint.str() + ".pem";

		generate_rsa_key_files(privateFileName.c_str(), publicFileName.c_str(), kbits, CRSAType::PKCS_PEM);
	}
}

int main()
{
	test_generate_rsa_key_files();
	return 0;
}