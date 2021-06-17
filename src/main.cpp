#include "CertificateManager.hpp"
#include "logging.h"
#include "adapter_asm.hpp"
#include "adapter_db.hpp"

#define CERTIFICATE_MANAGER_SERVICE_NAME "com.webos.service.certificatemanager"

static GMainLoop *gmainloop = nullptr;
//static GMainLoop *gmainLoopAsmAdapter = nullptr;

int main(int argc, char **argv)
{
	LOG_INFO(MSGID_MAINAPP, 0, "Certificate Manager start");

	gmainloop 			= g_main_loop_new(NULL, FALSE);
	//gmainLoopAsmAdapter	= g_main_loop_new(NULL, FALSE);

	try
	{
		LOG_INFO(MSGID_MAINAPP, 0, "create certificateManager");

		// Handler
		LSUtils::LunaService certificateManagerLunaHandler(CERTIFICATE_MANAGER_SERVICE_NAME, gmainloop);
		CertificateManager certificateManager(certificateManagerLunaHandler);

		// Adapter
		//LSUtils::LunaService asmAdapterLunaHandler("com.webos.service.certificatemanager.asmAdapter", gmainLoopAsmAdapter);
		//AdapterAsm AdapterAsm(asmAdapterLunaHandler.getHandle(), "com.webos.service.certificatemanager.asmAdapter");
		AdapterDb AdapterDb(certificateManagerLunaHandler.getHandle(), CERTIFICATE_MANAGER_SERVICE_NAME);
		AdapterAsm AdapterAsm(certificateManagerLunaHandler.getHandle(), CERTIFICATE_MANAGER_SERVICE_NAME);

		g_main_loop_run(gmainloop);
		//g_main_loop_run(gmainLoopAsmAdapter);
	}
	catch(LS::Error &err)
	{
		LOG_INFO(MSGID_MAINAPP, 0, "create error");
		std::cerr << err << std::endl;
		return 1;
	}

	g_main_loop_unref(gmainloop);
	//g_main_loop_unref(gmainLoopAsmAdapter);

	return 0;
}