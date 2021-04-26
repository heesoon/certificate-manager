#ifndef OPENSSLCERTWRAPPER_HPP_INCLUDED
#define OPENSSLCERTWRAPPER_HPP_INCLUDED

#include <memory>
#include "OpensslBioWrapper.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>

class OpensslCertWrapper
{
public:
    OpensslCertWrapper();
    bool open(const std::string &filename, char mode, int format);
    bool read();
    bool write(X509 *x509);
    bool close();
    X509* getX509();
    virtual ~OpensslCertWrapper();

private:
    X509 *x509 = NULL;
    int format = 0;
    std::unique_ptr<OpensslBioWrapper> upOpensslBioWrapper;
};
#endif