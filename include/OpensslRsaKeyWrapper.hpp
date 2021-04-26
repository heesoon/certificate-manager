#ifndef OPENSSLRSAKEYWRAPPER_HPP_INCLUDED
#define OPENSSLRSAKEYWRAPPER_HPP_INCLUDED

#include <memory>
#include "OpensslBioWrapper.hpp"
#include <openssl/evp.h>

enum class PKEY_TYPE_T
{
    PKEY_PRIVATE_KEY,
    PKEY_PUBLIC_KEY
};

class OpensslRsaKeyWrapper
{
public:
    OpensslRsaKeyWrapper();
    bool open(const std::string &inputKeyFilename, char mode, int format, int nBits);
    bool read(PKEY_TYPE_T pkeyType);
    bool write(PKEY_TYPE_T pkeyType, const std::string &outputKeyFilename, const std::string &passwd, const std::string &cipherName);
    bool close();
    EVP_PKEY* getPkey();
    virtual ~OpensslRsaKeyWrapper();

private:
    EVP_PKEY *pkey = NULL;
    int format = 0;
    std::unique_ptr<OpensslBioWrapper> upOpensslBioWrapper;
    bool createRsaPkey(int nBits);
};
#endif