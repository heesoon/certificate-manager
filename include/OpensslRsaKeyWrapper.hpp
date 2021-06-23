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
    bool open(const std::string &inputKeyFilename, char mode, int format);
    bool read(PKEY_TYPE_T pkeyType, const std::string &passwd);
    bool write(EVP_PKEY *pkey, PKEY_TYPE_T pkeyType, const std::string &passwd, const std::string &cipherName);
    void close();
    EVP_PKEY* getPkey();
    bool createRsaPkey(int nBits);
    virtual ~OpensslRsaKeyWrapper();

protected:
    //bool createRsaPkey(int nBits);

private:
    EVP_PKEY *pkey = NULL;
    std::unique_ptr<OpensslBioWrapper> upBio;
};
#endif