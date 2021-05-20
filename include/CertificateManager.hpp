#include <memory>
#include <luna-service2/lunaservice.hpp>
#include <pbnjson.hpp>

class CertificateManager : public LS::Handle
{
public :
	CertificateManager(const char *serviceName) : LS::Handle(LS::registerService(serviceName)), upGmainLoop{ g_main_loop_new(nullptr, false), g_main_loop_unref }{};
	CertificateManager(CertificateManager const&) = delete;
	CertificateManager(CertificateManager &&) = delete;
	CertificateManager& operator =(CertificateManager const&) = delete;
	CertificateManager& operator =(CertificateManager && ) = delete;
	
	void run();
	bool csr(LSMessage &message);
	bool sign(LSMessage &message);
	bool verify(LSMessage &message);

private :
	//using upGMainLoop = std::unique_ptr<GMainLoop, void(*)(GMainLoop*)>;
	//upGMainLoop mainLoop = { g_main_loop_new(nullptr, false), g_main_loop_unref };
	std::unique_ptr<GMainLoop, void(*)(GMainLoop*)> upGmainLoop;
};