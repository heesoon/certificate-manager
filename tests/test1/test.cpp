#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>

bool create_RSA_privateKey(const char* filename, int kBits)
{
	int rc = 1;
	BIGNUM *bn = NULL;
	BIO *pem = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;

	pem = BIO_new_file(filename, "w");
	if(pem == NULL)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;		
	}

	bn = BN_new();
	if(bn == NULL)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;		
	}

	rc = BN_set_word(bn, RSA_F4);
	if(rc == 0)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;			
	}

	rsa = RSA_new();
	if(rsa == NULL)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;
	}

	rc = RSA_generate_key_ex(rsa, kBits, bn, NULL);
	if(rc == 0)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;			
	}

	pkey = EVP_PKEY_new();
	if(pkey == NULL)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;		
	}

	rc = EVP_PKEY_set1_RSA(pkey, rsa);
	if(rc == 0)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;			
	}
	
 	// Write private key in PKCS PEM.
    rc = PEM_write_bio_PrivateKey(pem, pkey, NULL, NULL, 0, NULL, NULL);
	if(rc == 0)
	{
		std::cout << "error in " << __FUNCTION__ << " : " << __LINE__ << std::endl;
		goto err;			
	}

	return true;
err:

	if(pem)
	{
		BIO_free_all(pem);
	}

	if(bn)
	{
		BN_free(bn);
	}

	if(rsa)
	{
		RSA_free(rsa);
	}

	if(pkey)
	{
		EVP_PKEY_free(pkey);
	}

	return false;
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