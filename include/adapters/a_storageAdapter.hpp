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

#ifndef A_ADAPTOR_STORAGE_HPP_
#define A_ADAPTOR_STORAGE_HPP_

/*-----------------------------------------------------------------------------
 (File Inclusions)
 ------------------------------------------------------------------------------*/
#include <string>
#include <luna-service2++/handle.hpp>
#include "lunaservice_client.h"
#include "lunaservice_utils.h"

class StorageAdapter
{
public:
    StorageAdapter(LS::Handle *handle, std::string serviceName);
    ~StorageAdapter();
    static StorageAdapter* getInstance();
private:
    std::vector<std::string> deviceUris;
    std::string m_serviceName;
    static StorageAdapter *_instance;
    LSUtils::PersistentSubscription m_getStorageDevicePathSubscription;
    USUtils::LunaClient m_lunaClient;
    LSMessageToken m_callToken;

    // subscribe callback
    void getStorageDevicePathSubscriptionCb(LSUtils::LunaResponse &response);
};

#endif /*A_ADAPTOR_STORAGE_HPP_*/