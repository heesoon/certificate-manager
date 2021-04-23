#include <openssl/evp.h>
#include <openssl/pem.h>

#if 0
enum class ENUM_KEY_TYPE
{
    LOADED_FROM_FILE    = 1,
    NEW_CREATED         = 2
};
#endif

class KeyWrapper
{
public:
    KeyWrapper();
    bool loadPrivateKey(const std::string &inputKeyFilename, int format);
    bool loadPublicKey(const std::string &inputKeyFilename, int format);
    bool savePrivateKey(const std::string &outputKeyFilename, int format);
    bool savePrivateKey(const std::string &outputKeyFilename, const std::string &passwd, const std::string &cipherName, int format);
    bool savePublicKey(const std::string &outputKeyFilename, int format);
    bool createRsaKey(int nBits);
#if 0    
    EVP_PKEY* getEvpPrivateKey(ENUM_KEY_TYPE keyType);
    EVP_PKEY* getEvpPubliceKey(ENUM_KEY_TYPE keyType);
#endif
    EVP_PKEY* getLoadedEvpPrivateKey();
    EVP_PKEY* getLoadedEvpPubliceKey();
    EVP_PKEY* getCreatedEvpRsaKey();
    virtual ~KeyWrapper();
private:
    EVP_PKEY *loadedPrivateKey = NULL;
    EVP_PKEY *loadedPublicKey = NULL;
    EVP_PKEY *createdRsaKey = NULL;
};