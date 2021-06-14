#include "CertificateManager.hpp"
#include "logging.h"
#include "adapter_asm.hpp"

#define CERTIFICATE_MANAGER_SERVICE_NAME "com.webos.service.certificatemanager"

static GMainLoop *gmainloop = nullptr;

int main(int argc, char **argv)
{
	LOG_INFO(MSGID_MAINAPP, 0, "Certificate Manager start");

	gmainloop = g_main_loop_new(NULL, FALSE);

	try
	{
		LOG_INFO(MSGID_MAINAPP, 0, "create certificateManager");

		// Handler
		LSUtils::LunaService _lunaHandler(CERTIFICATE_MANAGER_SERVICE_NAME, gmainloop);
		CertificateManager certificateManager(_lunaHandler);

		// Adapter
		AdapterAsm AdapterAsm(_lunaHandler.getHandle(), CERTIFICATE_MANAGER_SERVICE_NAME);

		g_main_loop_run(gmainloop);
	}
	catch(LS::Error &err)
	{
		LOG_INFO(MSGID_MAINAPP, 0, "create error");
		std::cerr << err << std::endl;
		return 1;
	}

	g_main_loop_unref(gmainloop);

	return 0;
}