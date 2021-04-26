#include "Log.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include <openssl/pem.h>

OpensslRsaKeyWrapper::OpensslRsaKeyWrapper()
{
    pkey = NULL;
}

bool OpensslRsaKeyWrapper::createRsaPkey(int nBits)
{
#if 0
    bool ret = false;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(ctx == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto error;
    }

    if(EVP_PKEY_keygen_init(ctx) <= 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto error;
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nBits) <= 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto error;
    }

    if(EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        goto error;
    }

    ret = true;

error:

    EVP_PKEY_CTX_free(ctx);
    return ret;
#else
    auto delRawPtrEvpPkeyCtx = [](EVP_PKEY_CTX *ctx)
    {
        EVP_PKEY_CTX_free(ctx);
        PmLogDebug("[%s, %d] delRawPtrEvpPkeyCtx called ..", __FUNCTION__, __LINE__);
    };
    using unique_ptr_evpPkeyCtx_type_t = std::unique_ptr<EVP_PKEY_CTX, decltype(delRawPtrEvpPkeyCtx)>;

    unique_ptr_evpPkeyCtx_type_t upEvpPkeyCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), delRawPtrEvpPkeyCtx);
    if(upEvpPkeyCtx == nullptr)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(EVP_PKEY_keygen_init(upEvpPkeyCtx.get()) <= 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(upEvpPkeyCtx.get(), nBits) <= 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(EVP_PKEY_keygen(upEvpPkeyCtx.get(), &pkey) <= 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
#endif
}

bool OpensslRsaKeyWrapper::open(const std::string &inputKeyFilename, char mode, int format, int nBits)
{
    if(inputKeyFilename.empty() == true)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(mode == 'w')
    {
        // create new rsa key
        if(nBits < 2048)
        {
            PmLogError("[%s, %d] Key Size Too Short", __FUNCTION__, __LINE__);
            return false;
        }

        if(createRsaPkey(nBits) == false)
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }

    std::unique_ptr<OpensslBioWrapper> upInternalOpensslBioWrapper(new OpensslBioWrapper());
    if(upInternalOpensslBioWrapper == nullptr)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(upInternalOpensslBioWrapper->open(inputKeyFilename, mode, format) == false)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    format = format;
    upOpensslBioWrapper = std::move(upInternalOpensslBioWrapper);

    return true;
}

bool OpensslRsaKeyWrapper::read(PKEY_TYPE_T pkeyType)
{
    BIO *bio = NULL;

    bio = upOpensslBioWrapper->getBio();
    if(bio == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(pkeyType == PKEY_TYPE_T::PKEY_PRIVATE_KEY)
    {
        if(format == FORMAT_ASN1)
        {
            pkey = d2i_PrivateKey_bio(bio, NULL);
        }
        else if(format == FORMAT_PKCS12)
        {
            // TO DO.
            return false;
        }
    }
    else if(pkeyType == PKEY_TYPE_T::PKEY_PUBLIC_KEY)
    {
        if(format == FORMAT_ASN1)
        {
            pkey = d2i_PUBKEY_bio(bio, NULL);
        }
        else if(format == FORMAT_PEMRSA)
        {
            // TO DO.
            return false;
        }
        else if(format == FORMAT_PEM)
        {
            pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        }
        else
        {
            return false;
        }
    }
    else
    {
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
    }

    if(pkey == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

bool OpensslRsaKeyWrapper::write(PKEY_TYPE_T pkeyType, const std::string &outputKeyFilename, const std::string &passwd, const std::string &cipherName)
{
    BIO *bio = NULL;
    const EVP_CIPHER *cipherp = NULL;
    char *password = NULL;

    bio = upOpensslBioWrapper->getBio();
    if(bio == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if( (passwd.empty() == false) && (cipherName.empty() == false) )
    {
        // keygeneration with encryption and password.        
        if(passwd.size() < 4 || passwd.size() > 8)
        {
            // too much short password so return.
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
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
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }

    if(pkeyType == PKEY_TYPE_T::PKEY_PRIVATE_KEY)
    {
        // refer from pkey.c 241 line
        if(format == FORMAT_ASN1)
        {
            if(!i2d_PrivateKey_bio(bio, pkey))
            {
                PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                return false;
            }
        }
        else if(format == FORMAT_PEM)
        {
            //if(!PEM_write_bio_PrivateKey(key, createdRsaKey, EVP_aes_256_cbc(), (unsigned char*)"password", sizeof("password"), NULL, NULL))
            if(!PEM_write_bio_PrivateKey(bio, pkey, cipherp, (unsigned char*)password, sizeof(password), NULL, NULL))
            {
                PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                return false;
            }
        }
        else
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }
    else if(pkeyType == PKEY_TYPE_T::PKEY_PUBLIC_KEY)
    {
        if(format == FORMAT_ASN1)
        {
            if(!i2d_PUBKEY_bio(bio, pkey))
            {
                PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                return false;
            }
        }
        else if(format == FORMAT_PEM)
        {
            if(!PEM_write_bio_PUBKEY(bio, pkey))
            {
                PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
                return false;
            }
        }
        else
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }
    else
    {
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
    }

    return true;
}

EVP_PKEY* OpensslRsaKeyWrapper::getPkey()
{
    return pkey;
}

bool OpensslRsaKeyWrapper::close()
{
    EVP_PKEY_free(pkey);
    pkey = NULL;
    return true;
}

OpensslRsaKeyWrapper::~OpensslRsaKeyWrapper()
{
    EVP_PKEY_free(pkey);
    PmLogDebug("[%s, %d]", __FUNCTION__, __LINE__);
}