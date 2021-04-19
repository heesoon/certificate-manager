#include <iostream>
#include <memory>
#include <cassert>
#include "biowrapper.hpp"

BioWrapper::BioWrapper()
{
	bio = NULL;
}

int BioWrapper::isText(int format)
{
	return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

const char* BioWrapper::modestr(char mode, int format)
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

bool BioWrapper::open(const char *filename, char mode, int format)
{
	BIO *ret = NULL;

	if(filename == NULL)
	{
		std::cout << "error : filename" << std::endl;
		return false;
	}

	ret = BIO_new_file(filename, modestr(mode, format));
	if(ret == NULL)
	{
		std::cout << "Bio_new_file NULL" << std::endl;
		return false;
	}

	bio = ret;

	return true;
}

BioWrapper::~BioWrapper()
{
	if(bio != NULL)
	{
		BIO_free(bio);
	}

	std::cout << "~BioWrapper called.." << std::endl;
}