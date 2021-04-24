#include <iostream>
#include "bioWrapper.hpp"
#include "CertWrapper.hpp"

CertWrapper::CertWrapper()
{
    x509 = NULL;
}

bool CertWrapper::readCert(const std::string &inputFileName, int format)
{
    bool ret = false;
    BIO *cert = NULL;
    X509 *retx509 = NULL;
    BioWrapper bioWrapper;

    if(inputFileName.empty() == true)
    {
        return false;
    }

    ret = bioWrapper.open(inputFileName, 'r', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    cert = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        retx509 = d2i_X509_bio(cert, NULL);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        std::cout << "currently not support" << std::endl;
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        retx509 = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(retx509 == NULL)
    {
        return false;
    }

    x509 = retx509;
    return true;
}

bool CertWrapper::writeCert(X509 *x509, const std::string &outputFileName, int format)
{
    bool ret = false;
    BIO *cert = NULL;
    BioWrapper bioWrapper;

    if(outputFileName.empty() == true)
    {
        return false;
    }

    ret = bioWrapper.open(outputFileName, 'w', format);
    if(ret == false)
    {
        std::cout << "open bio error" << std::endl;
        return false;
    }

    cert = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        ret = i2d_X509_bio(cert, x509);
    }
    else if(format == FORMAT_PKCS12)
    {
        // TO DO.
        std::cout << "currently not support" << std::endl;
        return false;
    }
    else if(format == FORMAT_PEM)
    {
        ret = PEM_write_bio_X509_AUX(cert, x509);
        //ret = PEM_write_bio_X509(cert, x509);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(ret == 0)
    {
        return false;
    }

    return true;
}

X509* CertWrapper::getX509()
{
    return x509;
}

CertWrapper::~CertWrapper()
{
    X509_free(x509);
    std::cout << "~CertWrapper called.." << std::endl;
}