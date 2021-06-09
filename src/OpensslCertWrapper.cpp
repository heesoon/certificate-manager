//#include "Log.hpp"
#include "logging.h"
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
        return false;
    }

    std::unique_ptr<OpensslBioWrapper> upTempBio(new OpensslBioWrapper());
    if(upTempBio == nullptr)
    {
        return false;
    }

    if(upTempBio->open(filename, mode, format) == false)
    {
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
        return false;
    }

    mode = upBio->getOpenMode();
    if(mode != 'r')
    {
        return false;
    }

    bio = upBio->getBio();
    if(bio == NULL)
    {
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
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    }
    else
    {
        return false;
    }

    if(x509 == NULL)
    {
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
        return false;
    }

    if(upBio == nullptr)
    {
        return false;
    }

    mode = upBio->getOpenMode();
    if(mode != 'w')
    {
        return false;
    }

    bio = upBio->getBio();
    if(bio == NULL)
    {
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
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        ret = PEM_write_bio_X509_AUX(bio, x509);
        //ret = PEM_write_bio_X509(cert, x509);
    }
    else
    {
        return false;
    }

    if(ret == 0)
    {
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
}