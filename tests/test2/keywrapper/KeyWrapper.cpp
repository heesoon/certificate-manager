#include <iostream>
#include <memory>
#include <cassert>
//#include <regex>
#include "bioWrapper.hpp"
#include "KeyWrapper.hpp"

KeyWrapper::KeyWrapper()
{
    EVP_PKEY *loadedPrivateKey = NULL;
    EVP_PKEY *loadedPublicKey = NULL;
    EVP_PKEY *createdRsaKey = NULL;
}

bool KeyWrapper::loadPrivateKey(const std::string &inputKeyFilename, int format)
{
    bool ret = false;
    BioWrapper bioWrapper;
    
    assert(format == FORMAT_ASN1 || format == FORMAT_PKCS12 || format == FORMAT_PEM);

    ret = bioWrapper.open(inputKeyFilename, 'r', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    BIO *key = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        loadedPrivateKey = d2i_PrivateKey_bio(key, NULL);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        std::cout << "currently not support" << std::endl;
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        loadedPrivateKey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(loadedPrivateKey == NULL)
    {
        return false;
    }
	
	return true;
}

bool KeyWrapper::loadPublicKey(const std::string &inputKeyFilename, int format)
{
    bool ret = false;
    BioWrapper bioWrapper;
    
    assert(format == FORMAT_ASN1 || format == FORMAT_PEMRSA || format == FORMAT_PEM);

    ret = bioWrapper.open(inputKeyFilename, 'r', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    BIO *key = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        loadedPublicKey = d2i_PUBKEY_bio(key, NULL);
    }
    else if(format == FORMAT_PEMRSA)
    {
         // TO DO.
        std::cout << "currently not support" << std::endl;
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        loadedPublicKey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(loadedPublicKey == NULL)
    {
        return false;
    }
	
	return true;
}

bool KeyWrapper::savePrivateKey(const std::string &outputKeyFilename, int format)
{
    bool ret = false;
    BioWrapper bioWrapper;

    if(createdRsaKey == NULL)
    {
        return false;
    }

    assert(format == FORMAT_ASN1 || format == FORMAT_PEM);

    ret = bioWrapper.open(outputKeyFilename, 'w', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    BIO *key = bioWrapper.getBio();

    // refer from pkey.c 241 line
    if(format == FORMAT_ASN1)
    {
        if(!i2d_PrivateKey_bio(key, createdRsaKey))
        {
            return false;
        }
    }
    else if(format == FORMAT_PEM)
    {
        if(!PEM_write_bio_PrivateKey(key, createdRsaKey, NULL, NULL, 0, NULL, NULL))
        {
            return false;
        }
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

	return true;
}

bool KeyWrapper::savePrivateKey(const std::string &outputKeyFilename, const std::string &passwd, const std::string &cipherName, int format)
{
    bool ret = false;
    const EVP_CIPHER *cipherp = NULL;
    char *password = NULL;
    //const char *password = NULL;    
    BioWrapper bioWrapper;

    if(createdRsaKey == NULL)
    {
        return false;
    }

    if( (passwd.empty() == false) && (cipherName.empty() == false) )
    {
        // keygeneration with encryption and password.
        if(passwd.size() < 8)
        {
            // too much short password so return.
            return false;
        }

#if 0
        if(std::regex_match(passwd, std::regex("(\\+|-)?[0-9]*(\\.?([0-9]+))$")))
        {
            // all character is number;
            return false;
        }
#endif

        password = const_cast<char *>(passwd.c_str());
        //password = passwd.c_str();
        cipherp = EVP_get_cipherbyname(cipherName.c_str());
        if(cipherp == NULL)
        {
            std::cout << "error" << std::endl;
            return false;
        }
    }

    assert(format == FORMAT_ASN1 || format == FORMAT_PEM);

    ret = bioWrapper.open(outputKeyFilename, 'w', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    BIO *key = bioWrapper.getBio();

    // refer from pkey.c 241 line
    if(format == FORMAT_ASN1)
    {
        if(!i2d_PrivateKey_bio(key, createdRsaKey))
        {
            return false;
        }
    }
    else if(format == FORMAT_PEM)
    {
        //if(!PEM_write_bio_PrivateKey(key, createdRsaKey, EVP_aes_256_cbc(), (unsigned char*)password, sizeof(password), NULL, NULL))
        if(!PEM_write_bio_PrivateKey(key, createdRsaKey, cipherp, (unsigned char*)password, sizeof(password), NULL, NULL))
        {
            return false;
        }
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }
    std::cout << "Success " << std::endl;
	return true;
}

bool KeyWrapper::savePublicKey(const std::string &outputKeyFilename, int format)
{
    bool ret = false;
    BioWrapper bioWrapper;

    if(createdRsaKey == NULL)
    {
        return false;
    }

    assert(format == FORMAT_ASN1 || format == FORMAT_PEM);

    ret = bioWrapper.open(outputKeyFilename, 'w', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    BIO *key = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        if(!i2d_PUBKEY_bio(key, createdRsaKey))
        {
            return false;
        }
    }
    else if(format == FORMAT_PEM)
    {
        if(!PEM_write_bio_PUBKEY(key, createdRsaKey))
        {
            return false;
        }
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

	return true;
}

#if 0

EVP_PKEY* KeyWrapper::getEvpPrivateKey(ENUM_KEY_TYPE keyType)
{
    if(keyType == ENUM_KEY_TYPE::NEW_CREATED)
    {
        return createdRsaKey;
    }
    else if(keyType == ENUM_KEY_TYPE::LOADED_FROM_FILE)
    {
        return loadedPrivateKey;
    }
}

EVP_PKEY* KeyWrapper::getEvpPubliceKey(ENUM_KEY_TYPE keyType)
{
    if(keyType == ENUM_KEY_TYPE::NEW_CREATED)
    {
        return createdRsaKey;
    }
    else if(keyType == ENUM_KEY_TYPE::LOADED_FROM_FILE)
    {
        return loadedPublicKey;
    }
}
#endif

EVP_PKEY* KeyWrapper::getLoadedEvpPrivateKey()
{
    return loadedPrivateKey;
}

EVP_PKEY* KeyWrapper::getLoadedEvpPubliceKey()
{
    return loadedPublicKey;
}

EVP_PKEY* KeyWrapper::getCreatedEvpRsaKey()
{
    return createdRsaKey;
}

bool KeyWrapper::createRsaKey(int nBits)
{
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(ctx == NULL)
    {
        return false;
    }

    if(EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nBits) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;       
    }

    if(EVP_PKEY_keygen(ctx, &createdRsaKey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    return true;
}

KeyWrapper::~KeyWrapper()
{
    if(loadedPrivateKey != NULL)
    {
        EVP_PKEY_free(loadedPrivateKey);
    }

    if(loadedPublicKey != NULL)
    {
        EVP_PKEY_free(loadedPublicKey);
    }

    if(createdRsaKey != NULL)
    {
        EVP_PKEY_free(createdRsaKey);
    }

    std::cout << "~KeyWrapper called.." << std::endl;
}