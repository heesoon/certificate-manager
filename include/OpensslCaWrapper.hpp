#ifndef OPENSSLCAWRAPPER_HPP_INCLUDED
#define OPENSSLCAWRAPPER_HPP_INCLUDED

#include <memory>
#include <openssl/x509.h>
#include "OpensslBioWrapper"

class OpensslCaWrapper
{
public:
    OpensslCaWrapper();
    bool open(const std::string &filename, char mode, int format);
    bool read();
    bool write(X509 *x509);
    bool generateCertSignedByCa(const std::string &inputConfigFile, const std::string &inputCsrFile);
    //bool makeCsr(const std::string &inputCnfFilename, const std::string &inputKeyFilename, const subject_t &subject);
    //bool close();
    X509* getX509();
    virtual ~OpensslCaWrapper();

private:
    X509 *x509 = NULL;
    int format = 0;
    char mode;
    std::unique_ptr<OpensslBioWrapper> upOpensslBioWrapper;
};
#endif