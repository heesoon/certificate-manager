#ifndef OPENSSLBIOWRAPPER_HPP_INCLUDED
#define OPENSSLBIOWRAPPER_HPP_INCLUDED

#include <string>
#include <memory>
#include <openssl/bio.h>

# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)     /* Base64 */
# define FORMAT_ASN1     4                      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8                      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPublicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPublicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */

//using unique_ptr_bio_t = std::unique_ptr<BIO, void(*)(BIO *)>;

class OpensslBioWrapper
{
public:
    OpensslBioWrapper();
    bool open(const std::string &filename, char mode, int format);
	BIO* getBio();
    char getOpenMode();
    int getOpenFormat();    
	void close();
    virtual ~OpensslBioWrapper();

    //OpensslBioWrapper(OpensslBioWrapper const &) = delete;
    //OpensslBioWrapper &operator=(OpensslBioWrapper const &) = delete;

protected:
    int isText(int format);
    const char* modestr(char mode, int format);

private:
    char mode;
    int format;
    BIO *bio;
    //unique_ptr_bio_t upBio;    
};

#endif