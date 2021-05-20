#include "CertificateManager.hpp"

#define SERVICE_NAME "com.webos.service.certificateManager"

int main(int argc, char **argv)
{
	try
	{
		CertificateManager certificateManager(SERVICE_NAME);
		certificateManager.run();
	}
	catch(LS::Error &err)
	{
		std::cerr << err << std::endl;
		return 1;
	}

	return 0;
}