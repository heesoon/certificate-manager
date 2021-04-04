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
		ret = PEM_write_bio_PrivateKey_traditional(up_bio.get(), up_evp.get(), NULL, NULL, 0, NULL, NULL);
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

//https://groups.google.com/g/mailing.openssl.users/c/3QBaMeUdRBg
bool encrypt_RSA_by_privatekey(const char* filename, const char* infile, const char* outfile) 
{
	std::ifstream readFile;
	std::ofstream writeFile;

	if(filename == NULL)
	{
		LOGD("private filename empty")
		return false;
	}

	if(infile == NULL)
	{
		LOGD("filename empty")
		return false;
	}

	if(outfile == NULL)
	{
		LOGD("filename empty")
		return false;
	}

	UP_BIO up_bio(BIO_new_file(filename, "rb"), delPtrBIO);
	EVP_PKEY *pkey = PEM_read_bio_Parameters(up_bio.get(), NULL);
	if(pkey == NULL)
	{
		LOGE("called..")
		return false;
	}

	UP_EVP up_evp(std::move(pkey), delPtrEVP);
	//up_evp.reset(PEM_read_bio_Parameters(up_bio.get(), NULL));
	UP_EVP_CTX up_ctx(EVP_PKEY_CTX_new(up_evp.get(), NULL), delPtrEVPCTX);

	if(EVP_PKEY_encrypt_init(up_ctx.get()) <= 0)
	{
		LOGE("called..")
		return false;
	}

	if(EVP_PKEY_CTX_set_rsa_padding(up_ctx.get(), RSA_PKCS1_PADDING) <= 0)
	{
		LOGE("called..")
		return false;
	}

	readFile.open(infile);
	writeFile.open(outfile);
	if(readFile.is_open())
	{
		while(!readFile.eof())
		{
			char inbuff[256];
			char outbuff[256];
			size_t outlen = 0;
			
			readFile.getline(inbuff, 256);

			if(EVP_PKEY_encrypt(up_ctx.get(), (unsigned char*)outbuff, &outlen, (unsigned char*)inbuff, 256) <= 0)
			{
				LOGE("called..")
				readFile.close();
				writeFile.close();
				return false;
			}

			writeFile.write(outbuff, outlen); 
		}
		readFile.close();
		writeFile.close();
	}
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

void test_RSA_encrypt()
{
	encrypt_RSA_by_privatekey("privateKey-2048.pem", "Makefile", "encrypted.txt");
}

int main()
{
	test_RSA_privateKey();
	test_RSA_encrypt();
	return 0;
}