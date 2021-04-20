#include <iostream>
#include "CertWrapper.hpp"

CsrWrapper::CsrWrapper()
{
    x509ReadReq = NULL;
    x509WriteReq = NULL;
}

bool CsrWrapper::openCert()
{
    if(x509WriteReq != NULL)
    {
        return false;     
    }

    x509WriteReq = X509_REQ_new();
}

bool CsrWrapper::readCsr(const std::string &inputFileName, int format)
{
    bool ret = false;
    BIO *csr = NULL;
    X509_REQ *req = NULL;
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

    csr = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        req = d2i_X509_REQ_bio(csr, NULL);
    }
    else if(format == FORMAT_PEM)
    {
        req = PEM_read_bio_X509_REQ(csr, NULL, NULL, NULL);
    }
    else
    {
        std::cout << "currently not support" << std::endl;
        return false;
    }

    if(req == NULL)
    {
        return false;
    }

    x509ReadReq = req;
    return true;
}

bool CsrWrapper::writeCsr(const std::string &outputFileName, int format)
{
    bool ret = false;
    BIO *csr = NULL;
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

    csr = bioWrapper.getBio();

    if(format == FORMAT_ASN1)
    {
        ret = i2d_X509_REQ_bio(cert, x509WriteReq);
    }
    else if(format == FORMAT_PEM)
    {
        ret = PEM_write_bio_X509_REQ(csr, x509WriteReq);
        //ret = PEM_write_bio_X509_REQ_NEW(csr, x509);
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

bool CsrWrapper::makeCsr(const std::string &inputKeyFilename, const std::string &inputCnfFilename, const subject_t &subject)
{
	if(inputKeyFilename.empty() || inputCnfFilename.empty())
	{
		return false;
	}
}

X509_REQ* CsrWrapper::getX509ReadReq()
{
    return x509ReadReq;
}

X509_REQ* CsrWrapper::getX509WritedReq()
{
    return x509WriteReq;
}

CsrWrapper::~CsrWrapper()
{
    X509_REQ_free(x509ReadReq);
    X509_REQ_free(x509WriteReq);
    std::cout << "~CsrWrapper called.." << std::endl;
}