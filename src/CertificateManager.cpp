#include "CertificateManager.hpp"

const std::string service = "com.webos.service.certificateManager";
CertificateManager::CertificateManager() : LS::Handle(LS::registerService(service.c_str()))
{
	LS_CATEGORY_BEGIN(CertificateManager, "/")
		LS_CATEGORY_METHOD(csr)
		LS_CATEGORY_METHOD(sign)
		LS_CATEGORY_METHOD(verify)
	LS_CATEGORY_END

	//attach to mainloop and run it
	attachToLoop(upGmainLoop.get());
	// run the gmainloop
	g_main_loop_run(upGmainLoop.get());
}

bool CertificateManager::csr(LSMessage &message)
{
	 LS::Message request(&message);
	 request.respond(R"json({"bus":"public"})json");
	 return true;
}

bool CertificateManager::sign(LSMessage &message)
{
	 LS::Message request(&message);
	 request.respond(R"json({"bus":"public"})json");
	 return true;
}

bool CertificateManager::verify(LSMessage &message)
{
	 LS::Message request(&message);
	 request.respond(R"json({"bus":"public"})json");
	 return true;
}