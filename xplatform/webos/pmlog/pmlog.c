//#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "pmlog.h"

PmLogContext GetPmLogContext()
{
    static PmLogContext logContext = 0;
    if (0 == logContext)
    {
        PmLogGetContext("sample", &logContext);
    }
    return logContext;
}
