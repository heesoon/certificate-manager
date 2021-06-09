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

#ifndef LOG_HPP
#define LOG_HPP

#include <PmLogLib.h>

extern PmLogContext getPmLogContext();

#define LOG_CRITICAL(msgid, kvcount, ...) PmLogCritical(getPmgetPmLogContext()(), msgid, kvcount, ##__VA_ARGS__)
#define LOG_ERROR(msgid, kvcount, ...) PmLogError(getPmLogContext(), msgid, kvcount, ##__VA_ARGS__)
#define LOG_WARNING(msgid, kvcount, ...) PmLogWarning(getPmLogContext(), msgid, kvcount, ##__VA_ARGS__)
#define LOG_INFO(msgid, kvcount, ...) PmLogInfo(getPmLogContext(), msgid, kvcount, ##__VA_ARGS__)
#define NORMAL_LOG(msgid, kvcount, ...) PmLogInfo(getNormalLogContext(), msgid, kvcount, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) PmLogDebug(getPmLogContext(), "%s:%s() " fmt, __FILE__, __FUNCTION__, ##__VA_ARGS__)

#endif // LOG_HPP