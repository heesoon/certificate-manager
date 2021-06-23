#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslCertWrapper.hpp"

OpensslCertWrapper::OpensslCertWrapper()
{
    x509 = NULL;
}

bool OpensslCertWrapper::open(const std::string &filename, char mode, int format)
{
    if(filename.empty() == true)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    std::unique_ptr<OpensslBioWrapper> upTempBio(new OpensslBioWrapper());
    if(upTempBio == nullptr)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    if(upTempBio->open(filename, mode, format) == false)
    {
        PmLogError("[%s, %d] Bio open fail", __FUNCTION__, __LINE__);
        return false;
    }

    upBio = std::move(upTempBio);
    return true;
}

bool OpensslCertWrapper::read()
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
    if(format == FORMAT_ASN1)
    {
        x509 = d2i_X509_bio(bio, NULL);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    }
    else
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    if(x509 == NULL)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

bool OpensslCertWrapper::write(X509 *x509)
{
    int ret = 0;
    BIO *bio = NULL;
    char mode = ' ';
    int format = 0;

    if(x509 == NULL)
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

    format = upBio->getOpenFormat();
    if(format == FORMAT_ASN1)
    {
        ret = i2d_X509_bio(bio, x509);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        ret = PEM_write_bio_X509_AUX(bio, x509);
        //ret = PEM_write_bio_X509(cert, x509);
    }
    else
    {
        PmLogError("[%s, %d] Not Supported", __FUNCTION__, __LINE__);
        return false;
    }

    if(ret == 0)
    {
        PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

X509* OpensslCertWrapper::getX509()
{
	return x509;
}

void OpensslCertWrapper::close()
{
    X509_free(x509);
    x509 = NULL;
}

OpensslCertWrapper::~OpensslCertWrapper()
{
    X509_free(x509);
    PmLogDebug("[%s, %d]", __FUNCTION__, __LINE__);
}