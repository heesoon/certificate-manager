#include <iostream>
#include <memory>
#include <cassert>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"

OpensslBioWrapper::OpensslBioWrapper()
{
	bio = NULL;
}

int OpensslBioWrapper::isText(int format)
{
	return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

const char* OpensslBioWrapper::modestr(char mode, int format)
{
    assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return isText(format) ? "a" : "ab";
    case 'r':
        return isText(format) ? "r" : "rb";
    case 'w':
        return isText(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

bool OpensslBioWrapper::openBio(const std::string &filename, char mode, int format)
{
	BIO *ret = NULL;

	if(filename.empty())
	{
		PmLogError("[%s,%d] File Name Empty", __FUNCTION__, __LINE__);
		return false;
	}

	ret = BIO_new_file(filename.c_str(), modestr(mode, format));
	if(ret == NULL)
	{
		PmLogError("[%s,%d] BIO_new_file", __FUNCTION__, __LINE__);
		return false;
	}

	bio = ret;

	return true;
}

BIO* OpensslBioWrapper::getBio()
{
	return bio;
}

bool OpensslBioWrapper::closeBio()
{
	BIO_free(bio);
	bio = NULL;
	
	return true;
}

OpensslBioWrapper::~OpensslBioWrapper()
{
	BIO_free(bio);
	PmLogDebug("[%s,%d]", __FUNCTION__, __LINE__);
}