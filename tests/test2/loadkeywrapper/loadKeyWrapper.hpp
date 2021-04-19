#include "bioWrapper.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>

class LoadKeyWrapper
{
public:
    LoadKeyWrapper();
    bool loadPrivateKey(std::string inputKeyFilename, int format);
    bool loadPublicKey(std::string inputKeyFilename, int format);
    EVP_PKEY* getEvpPrivateKey();
    EVP_PKEY* getEvpPubliceKey();
    virtual ~LoadKeyWrapper();
private:
    EVP_PKEY *privatePkey = NULL;
    EVP_PKEY *publicPkey = NULL;
};