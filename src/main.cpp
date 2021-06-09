#include "CertificateManager.hpp"
#include "logging.h"

static GMainLoop *gmainloop = nullptr;

int main(int argc, char **argv)
{
	LOG_INFO(MSGID_MAINAPP, 0, "Certificate Manager start");

	gmainloop = g_main_loop_new(NULL, FALSE);

	try
	{
		LOG_INFO(MSGID_MAINAPP, 0, "create certificateManager");
		LSUtils::LunaService certificateService{"com.webos.service.certificatemanager", gmainloop};

		CertificateManager certificateManager(certificateService);

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