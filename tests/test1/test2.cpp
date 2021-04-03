#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/pem.h>

auto delPtrBIO = [](BIO *bio)
{
#ifdef __DEBUG__
	std::cout << delPtrBIO << " called .." << std::endl;
#endif	
	BIO_free(bio);
	// BIO_free_all(bio);
};

auto delPtrRSA = [](RSA *rsa)
{
#ifdef __DEBUG__
	std::cout << delPtrRSA << " called .." << std::endl;
#endif	
	RSA_free(rsa);
};

auto delPtrBN = [](BIGNUM *bn)
{
#ifdef __DEBUG__
	std::cout << delPtrBN << " called .." << std::endl;
#endif
	BN_free(bn);
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
#ifdef __DEBUG__
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
#endif
		return false;
	}

	rc = RSA_generate_key_ex(up_rsa.get(), kBits, up_bn.get(), NULL);
	if(rc == 0)
	{
#ifdef __DEBUG__
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
#endif
		return false;
	}

 	// Write private key in PKCS PEM.
    rc = PEM_write_bio_RSAPrivateKey(up_bio.get(), up_rsa.get(), NULL, NULL, 0, NULL, NULL);
	if(rc == 0)
	{
#ifdef __DEBUG__
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
#endif
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

		//std::cout << str << std::endl;

		create_RSA_privateKey(str.c_str(), a);
	}
}

int main()
{
	test_RSA_privateKey();

	return 0;
}