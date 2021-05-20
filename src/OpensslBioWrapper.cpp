#include <iostream>
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

bool OpensslBioWrapper::open(const std::string &filename, char mode, int format)
{
#if 1
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

	this->mode = mode;
	this->format = format;
	bio = ret;

	return true;
#else
	using unique_ptr_bio_t = std::unique_ptr<BIO, void(*)(BIO *)>;

	if(filename.empty())
	{
		PmLogError("[%s,%d] File Name Empty", __FUNCTION__, __LINE__);
		return false;
	}

	if(mode != 'w' || mode != 'r')
	{
		PmLogError("[%s,%d]", __FUNCTION__, __LINE__);
		return false;		
	}

	unique_ptr_bio_t upTempBio(BIO_new_file(filename.c_str(), modestr(mode, format)), BIO_free_all);
	if(upTempBio == nullptr)
	{
		return false;
	}

	this->mode = mode;
	this->format = format;
	bio = upTempBio.release();
	return true;
#endif
}

BIO* OpensslBioWrapper::getBio()
{
	return bio;
}

char OpensslBioWrapper::getOpenMode()
{
	return mode;
}

int OpensslBioWrapper::getOpenFormat()
{
	return format;	
}

void OpensslBioWrapper::close()
{
	BIO_free_all(bio);
	bio = NULL;
}

OpensslBioWrapper::~OpensslBioWrapper()
{
	BIO_free_all(bio);
	PmLogDebug("[%s,%d]", __FUNCTION__, __LINE__);
}
