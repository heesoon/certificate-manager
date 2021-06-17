

/* @@@LICENSE
 *
 * Copyright (c) 2013-2015 LG Electronics, Inc.
 *
 * Confidential computer software. Valid license from LG required for
 * possession, use or copying. Consistent with FAR 12.211 and 12.212,
 * Commercial Computer Software, Computer Software Documentation, and
 * Technical Data for Commercial Items are licensed to the U.S. Government
 * under vendor's standard commercial license.
 *
 * LICENSE@@@
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <string>
#include <luna-service2++/handle.hpp>
#include "lunaservice_utils.h"
#include "lunaservice_client.h"
#include "json_payload.hpp"
#include "logging.h"

bool checkLSMessageReply(LS::Call &call, LS_PLD::JSONPayload &payload, int timeout);
bool parsePalyLoadfromFile(const std::string &a_strFilePath, LS_PLD::JSONPayload &payload);

#endif
