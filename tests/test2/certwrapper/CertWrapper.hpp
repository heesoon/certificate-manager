#include "bioWrapper.hpp"
#include <string>
#include <openssl/x509.h>
#include <openssl/pem.h>

class CertWrapper
{
public:
    CertWrapper();
    //bool openCert(const std::string &inputFileName, int format);
    bool readCert(const std::string &inputFileName, int format);
    bool writeCert(const std::string &outputFileName, int format);
    X509* getX509();
    virtual ~CertWrapper();
private:
    X509 *x509;
};