#ifndef LOG_HPP_INCLUDED
#define LOG_HPP_INCLUDED

#if 0
#include <string>
enum class LogLevel
{
	Level_None		    = -1,	/* no output */
	Level_Emergency	    = 0,	/* system is unusable */
	Level_Alert		    = 1,	/* action must be taken immediately */
	Level_Critical	    = 2,	/* critical conditions */
	Level_Error		    = 3,	/* error conditions */
	Level_Warning	    = 4,	/* warning conditions */
	Level_Notice		= 5,	/* normal but significant condition */
	Level_Info		    = 6,	/* informational */
	Level_Debug		    = 7		/* debug-level messages */
};

class LogConfig
{
public:
    LogConfig(bool bEnable, LogLevel logLevel);
    void setLogLevel(LogLevel logLevel);
    void setlogEnable(bool bEnable);
    LogLevel getLogLevel();
    bool getlogEnable();
    virtual ~LogConfig();
private:
    bool isLogEnabled;
    LogLevel globalLogLevel;
};

class Log
{
public:
    Log(const std::string &logOwener, bool bEnable, LogLevel logLevel);
    void setLogLevel(LogLevel logLevel);
    void setlogEnable(bool bEnable);
    LogLevel getLogLevel();
    bool getlogEnable();
    virtual ~Log();
private:
    bool isLogEnabled;
    LogLevel logLevel;
    std::string logOwener;
};
#endif

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#if defined(LOG_PRINT)
#define MAX_BUFF_LENGTH 300
void PmLogMsg(const char* logContext, const char *fmt, ...);

#define PmLogDebug(fmt, ...)\
PmLogMsg("DEBUG", fmt, __VA_ARGS__)

#define PmLogError(fmt, ...)\
PmLogMsg("ERROR", fmt, __VA_ARGS__)

#define PmLogInfo(fmt, ...)\
PmLogMsg("INFO", fmt, __VA_ARGS__)

#else
#define MAX_BUFF_LENGTH 300
#define PmLogDebug(fmt, ...)
#define PmLogError(fmt, ...)
#define PmLogInfo(fmt, ...)

#endif
#endif