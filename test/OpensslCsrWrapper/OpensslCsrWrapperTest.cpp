#include <string>
#include <memory>
#include "Log.hpp"
#include "OpensslCsrWrapper.hpp"

void testMakeCsr()
{
	bool ret = false;
	X509_REQ *x509Req = NULL;
	const std::string outputFileName = "csr.pem";
	const std::string inputConfFileName = "../scripts/customer_openssl.cnf";
	const std::string inputPrivateKey = "../test/OpensslCsrWrapper/privatekey.pem";

	subject_t subject;
	subject.commonName = "Customer Inc";
	subject.countryName = "KR";
	subject.stateOrProvinceName = "Seoul";
	subject.localityName = "Seoul";
	subject.organizationName = "Customer Inc R&D";
	subject.emailAddress = "customer@rnd.com";

	std::unique_ptr<OpensslCsrWrapper> upOpenCsr(new OpensslCsrWrapper());
	if(upOpenCsr == nullptr)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	ret = upOpenCsr->open(outputFileName, 'w', FORMAT_PEM);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	ret = upOpenCsr->makeCsr(inputConfFileName, inputPrivateKey, subject);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	x509Req = upOpenCsr->getX509Req();
	if(x509Req == NULL)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	ret = upOpenCsr->write(x509Req);
	if(ret == false)
	{
		PmLogError("[%s, %d]", __FUNCTION__, __LINE__);
		return;
	}

	PmLogDebug("[%s, %d] Success", __FUNCTION__, __LINE__);

	//openssl req -noout -text -in csr.pem
}

int main()
{
	testMakeCsr();
	return 0;
}