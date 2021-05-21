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
	BIO *ret = NULL;

	if(filename.empty())
	{
		return false;
	}

	ret = BIO_new_file(filename.c_str(), modestr(mode, format));
	if(ret == NULL)
	{
		return false;
	}

	this->mode = mode;
	this->format = format;
	bio = ret;

	return true;
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
}
