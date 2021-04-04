#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
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

auto delPtrRSA = [](RSA *rsa)
{
	RSA_free(rsa);
	LOGD("called ..")
};

auto delPtrBN = [](BIGNUM *bn)
{
	BN_free(bn);
	LOGD("called ..")
};

auto delPtrEVP = [](EVP_PKEY *evp)
{
	EVP_PKEY_free(evp);
	LOGD("called ..")
};

auto delPtrEVPCTX = [](EVP_PKEY_CTX *ctx)
{
	EVP_PKEY_CTX_free(ctx);
	LOGD("called ..")
};

// type define unique_ptr for openssl pointers
// using UP_BIO = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using UP_BIO = std::unique_ptr<BIO, decltype(delPtrBIO)>;
using UP_RSA = std::unique_ptr<RSA, decltype(delPtrRSA)>;
using UP_BN = std::unique_ptr<BIGNUM, decltype(delPtrBN)>;
using UP_EVP = std::unique_ptr<EVP_PKEY, decltype(delPtrEVP)>;
using UP_EVP_CTX = std::unique_ptr<EVP_PKEY_CTX, decltype(delPtrEVPCTX)>;

enum class CRSAType
{
	TRADTIONAL_PEM,
	PKCS_PEM,
	PKCS8_PEM,
	ANS_DER
};

bool generate_RSA_keys(const char* filename, int kBits, CRSAType type)
{
	int ret = 1;
	int primes = DEFPRIMES;
	// UP_BIO up_bio(BIO_new_file(filename, "w"), ::BIO_free);

	if(filename == NULL)
	{
		LOGD("private filename empty")
		return false;
	}

	UP_EVP_CTX up_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), delPtrEVPCTX);
	ret = EVP_PKEY_keygen_init(up_ctx.get());
	if(ret <= 0)
	{
		LOGE("Error setting RSA Init")
		return false;
	}

	ret = EVP_PKEY_CTX_set_rsa_keygen_bits(up_ctx.get(), kBits);
	if(ret <= 0)
	{
		LOGE("Error setting RSA length")
		return false;
	}

	UP_BN up_bn(BN_new(), delPtrBN);
	ret = BN_set_word(up_bn.get(), RSA_F4);
	if(ret == 0)
	{
		LOGE("allocating RSA public exponent")
		return false;
	}

	ret = EVP_PKEY_CTX_set1_rsa_keygen_pubexp(up_ctx.get(), up_bn.get());
	if(ret <= 0)
	{
		LOGE("setting RSA public exponent")
		return false;
	}

	ret = EVP_PKEY_CTX_set_rsa_keygen_primes(up_ctx.get(), primes);
	if(ret <= 0)
	{
		LOGE("setting RSA public exponent")
		return false;
	}

	EVP_PKEY *evp =EVP_PKEY_new();
	ret = EVP_PKEY_keygen(up_ctx.get(), &evp);
	UP_EVP up_evp(std::move(evp), delPtrEVP);

	if(ret == 0)
	{
		LOGE("generating RSA key")
		return false;
	}

	UP_BIO up_bio(BIO_new_file(filename, "w"), delPtrBIO);
	if(type == CRSAType::TRADTIONAL_PEM)
	{
		//ret = PEM_write_bio_PrivateKey_traditional(up_bio.get(), up_evp.get(), NULL, NULL, 0, NULL, NULL);
	}
	else
	{
		ret = PEM_write_bio_PrivateKey(up_bio.get(), up_evp.get(), NULL, NULL, 0, NULL, NULL);
	}

	if(ret == 0)
	{
		LOGE("PEM file write")
		return false;
	}

	return true;
}

void test_RSA_privateKey()
{
	std::vector<int> kBits {1024, 2048, 4096};

	for( auto a : kBits)
	{
		std::string privateFileName = "privateKey-";
		//std::string publicFileName = "public-";
		std::stringstream sint;
		sint << a;

		privateFileName = privateFileName + sint.str() + ".pem";
		//publicFileName = publicFileName + sint.str() + ".pem";

		generate_RSA_keys(privateFileName.c_str(), a, CRSAType::PKCS_PEM);
	}
}

int main()
{
	test_RSA_privateKey();
	return 0;
}