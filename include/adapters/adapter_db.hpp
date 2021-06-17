// Copyright (c) 2019-2021 LG Electronics, Inc.
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

#ifndef ADAPTOR_DB_HPP_
#define ADAPTOR_DB_HPP_

/*-----------------------------------------------------------------------------
 (File Inclusions)
 ------------------------------------------------------------------------------*/
#include <string>
#include <luna-service2++/handle.hpp>
#include "lunaservice_client.h"
#include "lunaservice_utils.h"

class AdapterDb
{
public:
    AdapterDb(LS::Handle *handle, std::string serviceName);
    ~AdapterDb();

	void registerServiceStatus();
	void registerServiceStatusCb(LSUtils::LunaResponse &response);
	bool putKind();
	bool findKey(const std::string &keyId);
	bool put(const std::string &keyId);

    static AdapterDb* getInstance();

private:
    std::string mServiceName;
    static AdapterDb *_instance;
    LSUtils::PersistentSubscription mStatusSubscription;
    LSUtils::LunaClient mLunaClient;

	LS::Handle& handle_;
};

#endif /*ADAPTOR_DB_HPP_*/