#include <memory>
#include <luna-service2/lunaservice.hpp>
#include <pbnjson.hpp>

#define SERVICE_NAME "com.webos.service.certificateManager"

class CertificateManager : public LS::Handle
{
public :
	CertificateManager() : LS::Handle(LS::registerService(SERVICE_NAME)){}

	CertificateManager(CertificateManager const&) = delete;
	CertificateManager(CertificateManager &&) = delete;
	CertificateManager& operator =(CertificateManager const&) = delete;
	CertificateManager& operator =(CertificateManager && ) = delete;
	
	void run()
	{
		LS_CATEGORY_BEGIN(CertificateManager, "/")
			LS_CATEGORY_METHOD(csr)
			LS_CATEGORY_METHOD(sign)
			LS_CATEGORY_METHOD(verify)
		LS_CATEGORY_END

		//attach to mainloop and run it
		attachToLoop(mainLoop.get());
		g_main_loop_run(mainLoop.get());
	}

	bool csr(LSMessage &message)
	{
         LS::Message request(&message);
         request.respond(R"json({"bus":"public"})json");
         return true;
	}

	bool sign(LSMessage &message)
	{
         LS::Message request(&message);
         request.respond(R"json({"bus":"public"})json");
         return true;
	}

	bool verify(LSMessage &message)
	{
         LS::Message request(&message);
         request.respond(R"json({"bus":"public"})json");
         return true;
	}

private :
	using upGMainLoop = std::unique_ptr<GMainLoop, void(*)(GMainLoop*)>;
	upGMainLoop mainLoop = { g_main_loop_new(nullptr, false), g_main_loop_unref };
};

int main(int argc, char **argv)
{
	try
	{
		CertificateManager certificateManager;
		certificateManager.run();
	}
	catch(LS::Error &err)
	{
		std::cerr << err << std::endl;
		return 1;
	}

	return 0;
}