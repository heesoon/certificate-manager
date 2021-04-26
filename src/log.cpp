#include "log.hpp"

void PmLogMsg(const char* logContext, const char *fmt, ...)
{
    int n;
    char buf[MAX_BUFF_LENGTH] = {0, };

    va_list args;
    va_start(args, fmt);
    //va_copy(args2, args1);
    n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if(n > (sizeof(buf) -2))
    {
        return;
    }

    printf("[%s]: %s\n", logContext, buf);	
}