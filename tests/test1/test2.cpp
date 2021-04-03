#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/pem.h>

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

// type define unique_ptr for openssl pointers
// using UP_BIO = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using UP_BIO = std::unique_ptr<BIO, decltype(delPtrBIO)>;
using UP_RSA = std::unique_ptr<RSA, decltype(delPtrRSA)>;
using UP_BN = std::unique_ptr<BIGNUM, decltype(delPtrBN)>;
using UP_EVP = std::unique_ptr<EVP_PKEY, decltype(delPtrEVP)>;

enum class CRSAType
{
	TRADTIONAL_PEM,
	PKCS_PEM,
	PKCS8_PEM,
	ANS_DER
};

bool generate_RSA_keys(const char* privateFileName, const char* publicFileName, int kBits, CRSAType type)
{
	int rc = 1;
	// UP_BIO up_bio(BIO_new_file(filename, "w"), ::BIO_free);

	if(privateFileName == NULL)
	{
		LOGD("private filename empty")
		return false;
	}

	if(publicFileName == NULL)
	{
		LOGD("public filename empty")
		return false;
	}	

	UP_BIO up_bio_private(BIO_new_file(privateFileName, "w"), delPtrBIO);
	UP_BIO up_bio_public(BIO_new_file(publicFileName, "w"), delPtrBIO);
	UP_RSA up_rsa(RSA_new(), delPtrRSA);
	UP_BN up_bn(BN_new(), delPtrBN);
	UP_EVP up_evp(EVP_PKEY_new(), delPtrEVP);

	rc = BN_set_word(up_bn.get(), RSA_F4);
	if(rc == 0)
	{
		LOGE("called ..")
		return false;
	}

	rc = RSA_generate_key_ex(up_rsa.get(), kBits, up_bn.get(), NULL);
	if(rc == 0)
	{
		LOGE("called ..")
		return false;
	}

#if 0
	const BIGNUM *e;
	const BIGNUM *d;
	const BIGNUM *n;
	char *dece;
	char *decd;
	char *decn;

	RSA_get0_key(rsa, &n, &e, &d);
	dece = BN_bn2dec(e);
	decd = BN_bn2dec(d);
	decn = BN_bn2dec(n);

	std::cout << "e : " << dece <<  std::endl;
	std::cout << "d : " << decd <<  std::endl;
	std::cout << "n : " << decn <<  std::endl;

	OPENSSL_free(dece);
	OPENSSL_free(decd);
	OPENSSL_free(decn);
#endif

	rc = EVP_PKEY_set1_RSA(up_evp.get(), up_rsa.get());
	if(rc == 0)
	{
		LOGE("called ..")
		return false;
	}

	// Generate Private Key
	switch(type)
	{
		case CRSAType::TRADTIONAL_PEM :
			rc = PEM_write_bio_RSAPrivateKey(up_bio_private.get(), up_rsa.get(), NULL, NULL, 0, NULL, NULL);
		break;
		case CRSAType::PKCS_PEM :
			rc = PEM_write_bio_PrivateKey(up_bio_private.get(), up_evp.get(), NULL, NULL, 0, NULL, NULL);
		break;
		case CRSAType::PKCS8_PEM :
			rc = PEM_write_bio_PKCS8PrivateKey(up_bio_private.get(), up_evp.get(), NULL, NULL, 0, NULL, NULL);
		break;
		case CRSAType::ANS_DER :
			rc = i2d_RSAPrivateKey_bio(up_bio_private.get(), up_rsa.get());
		break;						
	}
 	
	if(rc == 0)
	{
		LOGE("called ..")
		return false;
	}

	// Generate Public Key
	switch(type)
	{
		case CRSAType::TRADTIONAL_PEM :
			rc = PEM_write_bio_PUBKEY(up_bio_public.get(), up_evp.get());
		break;
		case CRSAType::PKCS_PEM :
			rc = PEM_write_bio_RSAPublicKey(up_bio_public.get(), up_rsa.get());
		break;
		case CRSAType::PKCS8_PEM :
			rc = PEM_write_bio_RSAPublicKey(up_bio_public.get(), up_rsa.get());
		break;
		case CRSAType::ANS_DER :
			rc = i2d_RSAPublicKey_bio(up_bio_public.get(), up_rsa.get());
		break;
	}
 	
	if(rc == 0)
	{
		LOGE("called ..")
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
		std::string publicFileName = "public-";
		std::stringstream sint;
		sint << a;

		privateFileName = privateFileName + sint.str() + ".pem";
		publicFileName = publicFileName + sint.str() + ".pem";

		generate_RSA_keys(privateFileName.c_str(), publicFileName.c_str(), a, CRSAType::PKCS_PEM);
	}
}

int main()
{
	test_RSA_privateKey();
	return 0;
}