#include <string>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define BASE_SECTION            "ca"

#define ENV_DEFAULT_CA          "default_ca"

#define STRING_MASK             "string_mask"
#define UTF8_IN                 "utf8"

#define ENV_NEW_CERTS_DIR       "new_certs_dir"
#define ENV_CERTIFICATE         "certificate"
#define ENV_SERIAL              "serial"
#define ENV_RAND_SERIAL         "rand_serial"
#define ENV_CRLNUMBER           "crlnumber"
#define ENV_PRIVATE_KEY         "private_key"
#define ENV_DEFAULT_DAYS        "default_days"
#define ENV_DEFAULT_STARTDATE   "default_startdate"
#define ENV_DEFAULT_ENDDATE     "default_enddate"
#define ENV_DEFAULT_CRL_DAYS    "default_crl_days"
#define ENV_DEFAULT_CRL_HOURS   "default_crl_hours"
#define ENV_DEFAULT_MD          "default_md"
#define ENV_DEFAULT_EMAIL_DN    "email_in_dn"
#define ENV_PRESERVE            "preserve"
#define ENV_POLICY              "policy"
#define ENV_EXTENSIONS          "x509_extensions"
#define ENV_CRLEXT              "crl_extensions"
#define ENV_MSIE_HACK           "msie_hack"
#define ENV_NAMEOPT             "name_opt"
#define ENV_CERTOPT             "cert_opt"
#define ENV_EXTCOPY             "copy_extensions"
#define ENV_UNIQUE_SUBJECT      "unique_subject"
#define ENV_DATABASE            "database"

# define SERIAL_RAND_BITS        159

class CaWrapper
{
public:
    CaWrapper();
    bool init();
    bool setCertTimes(const char *startdate, const char *enddate, int days);
    int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);
    int do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts);
    int adapt_keyid_ext(X509 *cert, X509V3_CTX *ext_ctx, const char *name, const char *value, int add_default);
    int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);
    int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx);
    bool generateX509(X509_REQ *x509Req, X509 *x509Ca, EVP_PKEY *caPkey, BIGNUM *serial, long days, int email_dn, STACK_OF(CONF_VALUE) *policy,const EVP_MD *evpMd);
    bool ca(const std::string &inputConfigFile, const std::string &inputCsrFile);
    bool saveSignedCert(const std::string &outputFile, int format);
    X509_STORE* setup_verify(const std::string &inputCaFile);
    bool check(X509_STORE *ctx, const std::string &inputCertFile, bool show_chain);
    bool verify(const std::string &inputCaChainFile, const std::string &inputCertFile);
    virtual ~CaWrapper();
private:
    X509 *x509 = NULL;
    bool randSerial(BIGNUM *b, ASN1_INTEGER *ai);
    BIGNUM *loadSerial(const char *serialfile, int create, ASN1_INTEGER **retai);
};