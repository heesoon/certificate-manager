#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslCaWrapper.hpp"

void testCa()
{
	bool ret = false;
	const std::string filename = "csr.pem";
	std::unique_ptr<OpensslCaWrapper> upOpenCa(new OpensslCaWrapper());
	
	ret = upOpenCa->open(filename, 'w', FORMAT_PEM);
	if(ret == false)
	{
		return;
	}

	ret = upOpenCa->read();
	if(ret == false)
	{
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

int main()
{
	testCa();
	return 0;
}