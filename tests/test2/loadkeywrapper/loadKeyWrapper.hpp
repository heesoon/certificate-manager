#include "bioWrapper.hpp"
#include <openssl/evp.h>

class LoadKeyWrapper
{
public:
    LoadKeyWrapper();
    virtual ~LoadKeyWrapper();
private:
    EVP_PKEY *pkey;
};