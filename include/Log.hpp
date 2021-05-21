// Copyright (c) 2013-2020 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef LOG_HPP_INCLUDED
#define LOG_HPP_INCLUDED

#include "PmLogLib.h"

#define LOG_INFO(...)                 PmLogInfo(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_INFO_WITH_CLOCK(...)      PmLogInfoWithClock(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_DEBUG(...)                PmLogDebug(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_WARNING(...)              PmLogWarning(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)
#define LOG_ERROR(...)                PmLogError(GetCertificateManagerPmLogContext(), ##__VA_ARGS__)

#endif // LOG_HPP_INCLUDED