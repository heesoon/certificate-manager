#include "CertificateManager.hpp"

int main(int argc, char **argv)
{
	try
	{
		CertificateManager certificateManager;
	}
	catch(LS::Error &err)
	{
		std::cerr << err << std::endl;
		return 1;
	}

	return 0;
}