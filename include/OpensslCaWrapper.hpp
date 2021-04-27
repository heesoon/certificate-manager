#ifndef OPENSSLCAWRAPPER_HPP_INCLUDED
#define OPENSSLCAWRAPPER_HPP_INCLUDED

#include <memory>
#include <openssl/x509.h>
#include "OpensslBioWrapper.hpp"

class OpensslCaWrapper
{
public:
    OpensslCaWrapper();
    bool open(const std::string &filename, char mode, int format);
    bool read();
    bool write(X509 *x509);
    bool generateCertSignedByCa(const std::string &inputConfigFile, const std::string &inputCsrFile);
    bool verifyByCa(const std::string &inputCaChainFile, const std::string &inputCertFile);
    //bool close();
    X509* getX509();
    virtual ~OpensslCaWrapper();

protected:
    bool generateX509(X509 *x509, X509_REQ *x509Req, X509 *x509Ca, CONF *conf, const char *ext_sect, EVP_PKEY *caPkey, BIGNUM *serial, long days, int emailDn, STACK_OF(CONF_VALUE) *policy ,const EVP_MD *evpMd);
    bool randSerial(BIGNUM *b, ASN1_INTEGER *ai);
    BIGNUM* loadSerial(const char *serialfile, int create, ASN1_INTEGER **retai);
    bool setCertTimes(const char *startdate, const char *enddate, int days);
    int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);
    int do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts);
    int adapt_keyid_ext(X509 *cert, X509V3_CTX *ext_ctx, const char *name, const char *value, int add_default);
    int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);
    int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx);
    bool check(X509_STORE *ctx, const std::string &inputCertFile, bool show_chain);
    X509_STORE* setup_verify(const std::string &inputCaFile);

private:
    X509 *x509 = NULL;
    int format = 0;
    char mode;
    std::unique_ptr<OpensslBioWrapper> upOpensslBioWrapper;
};
#endif