#include <openssl/evp.h>
#include <openssl/pem.h>

enum class ENUM_KEY_TYPE
{
    LOADED_FROM_FILE    = 1,
    NEW_CREATED         = 2
};

class KeyWrapper
{
public:
    KeyWrapper();
    bool loadPrivateKey(const std::string &inputKeyFilename, int format);
    bool loadPublicKey(const std::string &inputKeyFilename, int format);
    bool savePrivateKey(const std::string &outputKeyFilename, int format);
    bool savePublicKey(const std::string &outputKeyFilename, int format);
    EVP_PKEY* getEvpPrivateKey(ENUM_KEY_TYPE keyType);
    EVP_PKEY* getEvpPubliceKey(ENUM_KEY_TYPE keyType);
    virtual ~KeyWrapper();
private:
    EVP_PKEY *loadedPrivateKey = NULL;
    EVP_PKEY *loadedPublicKey = NULL;
    EVP_PKEY *createdPrivateKey = NULL;
    EVP_PKEY *createdPublicKey = NULL;
};