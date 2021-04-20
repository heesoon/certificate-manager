#include <string>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define REQ_BASE_SECTION         "req"

#define BITS            "default_bits"
#define KEYFILE         "default_keyfile"
#define PROMPT          "prompt"
#define DISTINGUISHED_NAME      "distinguished_name"
#define ATTRIBUTES      "attributes"
#define V3_EXTENSIONS   "x509_extensions"
#define REQ_EXTENSIONS  "req_extensions"
#define STRING_MASK     "string_mask"
#define UTF8_IN         "utf8"

typedef struct st_subject
{
	std::string commonName;
	std::string countryName;
	std::string stateOrProvinceName;
	std::string localityName;
	std::string organizationName;
	std::string emailAddress;
} subject_t;

class CsrWrapper
{
public:
    CsrWrapper();
    bool openCert();
    bool readCsr(const std::string &inputFileName, int format);
    bool writeCsr(const std::string &outputFileName, int format);
    bool makeCsr(const std::string &inputKeyFilename, const std::string &inputCnfFilename, const subject_t &subject);
    X509_REQ* getX509ReadReq();
    X509_REQ* getX509WriteReq();
    virtual ~CsrWrapper();
private:
    X509_REQ *x509ReadReq = NULL;
    X509_REQ *x509WriteReq = NULL;
};