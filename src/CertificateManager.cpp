#include "CertificateManager.hpp"

/*
CertificateManager::CertificateManager(const char *serviceName)
{
	LS::Handle(LS::registerService(serviceName));
	upGmainLoop = std::move({ g_main_loop_new(nullptr, false), g_main_loop_unref });
}
*/

void CertificateManager::run()
{
	LS_CATEGORY_BEGIN(CertificateManager, "/")
		LS_CATEGORY_METHOD(csr)
		LS_CATEGORY_METHOD(sign)
		LS_CATEGORY_METHOD(verify)
	LS_CATEGORY_END

	//attach to mainloop and run it
	attachToLoop(upGmainLoop.get());
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