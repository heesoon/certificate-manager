#include <iostream>
#include "Log.hpp"
#include "OpensslRsaKeyWrapper.hpp"
#include <openssl/pem.h>

auto delRawPtrEvpPkeyCtx = [](EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_CTX_free(ctx);
    PmLogDebug("[%s, %d] delRawPtrEvpPkeyCtx called ..", __FUNCTION__, __LINE__);
};
using unique_ptr_evpPkeyCtx_type_t = std::unique_ptr<EVP_PKEY_CTX, decltype(delRawPtrEvpPkeyCtx)>;

OpensslRsaKeyWrapper::OpensslRsaKeyWrapper()
{
    pkey = NULL;
}

bool OpensslRsaKeyWrapper::createRsaPkey(int nBits)
{
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

    //if(nBits <= OPENSSL_RSA_FIPS_MIN_MODULUS_BITS || nBits >= OPENSSL_RSA_MAX_MODULUS_BITS)
    if(nBits <= 1024 || nBits >= 16384)
    {
        PmLogError("[%s, %d] Out of Valid Private Key Length (1024 ~ 16384)", __FUNCTION__, __LINE__);
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
        if(createRsaPkey(nBits) == false)
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }

    std::unique_ptr<OpensslBioWrapper> upTempBio(new OpensslBioWrapper());
    if(upTempBio == nullptr)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(upTempBio->open(inputKeyFilename, mode, format) == false)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    upBio = std::move(upTempBio);
    return true;
}

bool OpensslRsaKeyWrapper::open(const std::string &inputKeyFilename, char mode, int format)
{
    if(inputKeyFilename.empty() == true)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(mode != 'r')
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    std::unique_ptr<OpensslBioWrapper> upTempBio(new OpensslBioWrapper());
    if(upTempBio == nullptr)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(upTempBio->open(inputKeyFilename, mode, format) == false)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    upBio = std::move(upTempBio);
    return true;
}

bool OpensslRsaKeyWrapper::read(PKEY_TYPE_T pkeyType, const std::string &passwd)
{
    BIO *bio = NULL;
    char mode = ' ';
    int format = 0;

    if(upBio == nullptr)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    mode = upBio->getOpenMode();
    if(mode != 'r')
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    bio = upBio->getBio();
    if(bio == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    format = upBio->getOpenFormat();

    if(pkeyType == PKEY_TYPE_T::PKEY_PRIVATE_KEY)
    {
        if(format == FORMAT_ASN1)
        {
            pkey = d2i_PrivateKey_bio(bio, NULL);
        }
        else if(format == FORMAT_PEM)
        {
            pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
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
            if(passwd.empty() == true)
            {
                pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
            }
            else
            {
                char *password = const_cast<char *>(passwd.c_str());
                pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, password);
            }
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

bool OpensslRsaKeyWrapper::write(EVP_PKEY *pkey, PKEY_TYPE_T pkeyType, const std::string &passwd, const std::string &cipherName)
{
    BIO *bio = NULL;
    char mode = ' ';
    int format = 0;
    const EVP_CIPHER *cipherp = NULL;
    char *password = NULL;

    if(pkey == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(upBio == nullptr)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    mode = upBio->getOpenMode();
    if(mode != 'w')
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    bio = upBio->getBio();
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

        if (EVP_CIPHER_mode(cipherp) == EVP_CIPH_GCM_MODE ||
                EVP_CIPHER_mode(cipherp) == EVP_CIPH_CCM_MODE ||
                EVP_CIPHER_mode(cipherp) == EVP_CIPH_XTS_MODE ||
                EVP_CIPHER_mode(cipherp) == EVP_CIPH_OCB_MODE)
        {
            PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
            return false;
        }
    }

    format = upBio->getOpenFormat();

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

void OpensslRsaKeyWrapper::close()
{
    EVP_PKEY_free(pkey);
    pkey = NULL;
}

OpensslRsaKeyWrapper::~OpensslRsaKeyWrapper()
{
    EVP_PKEY_free(pkey);
    PmLogDebug("[%s, %d]", __FUNCTION__, __LINE__);
}