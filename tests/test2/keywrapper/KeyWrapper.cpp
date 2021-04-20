#include <iostream>
#include <memory>
#include <cassert>
#include "KeyWrapper.hpp"

KeyWrapper::KeyWrapper()
{
    privatePkey = NULL;
    publicPkey = NULL;
}

bool KeyWrapper::loadPrivateKey(std::string inputKeyFilename, int format)
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
        privatePkey = d2i_PrivateKey_bio(key, NULL);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        std::cout << "currently not support" << std::endl;
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        privatePkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(privatePkey == NULL)
    {
        return false;
    }
}

bool KeyWrapper::loadPublicKey(std::string inputKeyFilename, int format)
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
        publicPkey = d2i_PUBKEY_bio(key, NULL);
    }
    else if(format == FORMAT_PEMRSA)
    {
         // TO DO.
        std::cout << "currently not support" << std::endl;
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        publicPkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(publicPkey == NULL)
    {
        return false;
    }
}

EVP_PKEY* KeyWrapper::getEvpPrivateKey()
{
    return privatePkey;
}

EVP_PKEY* KeyWrapper::getEvpPubliceKey()
{
    return publicPkey;
}

KeyWrapper::~KeyWrapper()
{
    if(privatePkey != NULL)
    {
        EVP_PKEY_free(privatePkey);
    }

    if(publicPkey != NULL)
    {
        EVP_PKEY_free(publicPkey);
    }

    std::cout << "~KeyWrapper called.." << std::endl;
}