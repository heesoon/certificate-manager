#include <iostream>
#include <memory>
#include <cassert>
#include "bioWrapper.hpp"
#include "KeyWrapper.hpp"

KeyWrapper::KeyWrapper()
{
    EVP_PKEY *loadedPrivateKey = NULL;
    EVP_PKEY *loadedPublicKey = NULL;
    EVP_PKEY *createdPrivateKey = NULL;
    EVP_PKEY *createdPublicKey = NULL;
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

    if(createdPrivateKey == NULL)
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
        if(!i2d_PrivateKey_bio(key, createdPrivateKey))
        {
            return false;
        }
    }
    else if(format == FORMAT_PEM)
    {
        if(!PEM_write_bio_PrivateKey(key, createdPrivateKey, NULL, NULL, 0, NULL, NULL))
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

bool KeyWrapper::savePublicKey(const std::string &outputKeyFilename, int format)
{
    bool ret = false;
    BioWrapper bioWrapper;

    if(createdPublicKey == NULL)
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
        if(!i2d_PUBKEY_bio(key, createdPublicKey))
        {
            return false;
        }
    }
    else if(format == FORMAT_PEM)
    {
        if(!PEM_write_bio_PUBKEY(key, createdPublicKey))
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

EVP_PKEY* KeyWrapper::getEvpPrivateKey(ENUM_KEY_TYPE keyType)
{
    if(keyType == ENUM_KEY_TYPE::NEW_CREATED)
    {
        return createdPrivateKey;
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
        return createdPublicKey;
    }
    else if(keyType == ENUM_KEY_TYPE::LOADED_FROM_FILE)
    {
        return loadedPublicKey;
    }
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

    if(createdPrivateKey != NULL)
    {
        EVP_PKEY_free(createdPrivateKey);
    }

    if(createdPublicKey != NULL)
    {
        EVP_PKEY_free(createdPublicKey);
    }  

    std::cout << "~KeyWrapper called.." << std::endl;
}