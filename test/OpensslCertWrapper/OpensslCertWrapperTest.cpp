#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslCertWrapper.hpp"

void testCert()
{
	bool ret = false;
	const std::string filename = "cert.pem";
	std::unique_ptr<OpensslCertWrapper> upOpenCert(new OpensslCertWrapper());
	
	ret = upOpenCert->open(filename, 'r', FORMAT_PEM);
	if(ret == false)
	{
		return;
	}

	ret = upOpenCert->read();
	if(ret == false)
	{
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

int main()
{
	testCert();
	return 0;
}