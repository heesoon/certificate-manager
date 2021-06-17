#include "Utils.h"
#include <errno.h>
#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>

using namespace std;

std::string read_file(const std::string &path)
{
    std::ifstream file(path.c_str());
    if (file.good()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    }

    return "";
}

bool parsePalyLoadfromFile(const std::string &a_strFilePath, LS_PLD::JSONPayload &payload)
{
	std::string strContent = read_file(a_strFilePath);

	payload = LS_PLD::JSONPayload(strContent);

	return true;
}

/*
	ret = call.get(timeout)

	if ret is boolean, false is timeout return
*/
bool checkLSMessageReply(LS::Call &call, LS_PLD::JSONPayload &payload, int timeout)
{
    LS::Message reply = call.get(timeout);

	if(reply.get() == nullptr)
	{
		return false;
	}

	if(bool(reply) == false)
	{
		/* No reply in timout	*/
		return false;
	}

	if(reply.isHubError() == true)
	{
		/* lsHub error */
		return false;
	}

    payload = LS_PLD::JSONPayload(reply.getPayload());

	if(payload.isValid() == false)
	{
		return false;
	}

	return true;
}
