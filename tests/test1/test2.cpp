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

// type define unique_ptr for openssl pointers
// using UP_BIO = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using UP_BIO = std::unique_ptr<BIO, decltype(delPtrBIO)>;
using UP_RSA = std::unique_ptr<RSA, decltype(delPtrRSA)>;
using UP_BN = std::unique_ptr<BIGNUM, decltype(delPtrBN)>;

bool create_RSA_privateKey(const char* filename, int kBits)
{
	int rc = 1;
	// UP_BIO up_bio(BIO_new_file(filename, "w"), ::BIO_free);
	UP_BIO up_bio(BIO_new_file(filename, "w"), delPtrBIO);
	UP_RSA up_rsa(RSA_new(), delPtrRSA);
	UP_BN up_bn(BN_new(), delPtrBN);

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

 	// Write private key in PKCS PEM.
    rc = PEM_write_bio_RSAPrivateKey(up_bio.get(), up_rsa.get(), NULL, NULL, 0, NULL, NULL);
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
		std::string str = "privateKey-";
		std::stringstream sint;
		sint << a;
		str = str + sint.str() + ".pem";

		create_RSA_privateKey(str.c_str(), a);
	}
}

int main()
{
	test_RSA_privateKey();
	return 0;
}