#include "log.hpp"

void testLog()
{
	PmLogDebug("%s", "heesoon.kim");
	PmLogInfo("%s", "heesoon.kim");
	PmLogError("%s", "heesoon.kim");
}

int main()
{
	testLog();
	return 0;
}