#ifndef LOG_HPP_INCLUDED
#define LOG_HPP_INCLUDED

#include "PmLogLib.h"

#define LOG_INFO(...)                 PmLogInfo(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_INFO_WITH_CLOCK(...)      PmLogInfoWithClock(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_DEBUG(...)                PmLogDebug(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_WARNING(...)              PmLogWarning(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_ERROR(...)                PmLogError(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)

#endif // LOG_HPP_INCLUDED