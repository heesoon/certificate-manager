#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslBioWrapper.hpp"
#include "OpensslCsrWrapper.hpp"

void testCsr()
{
	bool ret = false;
	const std::string filename = "csr.pem";
	std::unique_ptr<OpensslCsrWrapper> upOpenCsr(new OpensslCsrWrapper());
	
	ret = upOpenCsr->open(filename, 'w', FORMAT_PEM);
	if(ret == false)
	{
		return;
	}

	ret = upOpenCsr->read();
	if(ret == false)
	{
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);
}

int main()
{
	testCsr();
	return 0;
}