#ifndef OPENSSLCSRWRAPPER_HPP_INCLUDED
#define OPENSSLCSRWRAPPER_HPP_INCLUDED

#include <memory>
#include "OpensslBioWrapper.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>

typedef struct st_subject
{
	std::string commonName;
	std::string countryName;
	std::string stateOrProvinceName;
	std::string localityName;
	std::string organizationName;
	std::string emailAddress;
} subject_t;

class OpensslCsrWrapper
{
public:
    OpensslCsrWrapper();
    bool open(const std::string &filename, char mode, int format);
    bool read();
    bool write(X509_REQ *x509Req);
    bool makeCsr(const std::string &inputCnfFilename, const std::string &inputKeyFilename, const subject_t &subject);
	X509_REQ* getX509Req();
    bool close();
    EVP_PKEY* getPkey();
    virtual ~OpensslCsrWrapper();

private:
    X509_REQ *x509Req = NULL;
    int format = 0;
    char mode;
    std::unique_ptr<OpensslBioWrapper> upOpensslBioWrapper;
};
#endif