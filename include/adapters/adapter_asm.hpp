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

#ifndef ADAPTOR_ASM_HPP_
#define ADAPTOR_ASM_HPP_

/*-----------------------------------------------------------------------------
 (File Inclusions)
 ------------------------------------------------------------------------------*/
#include <string>
#include <mutex>
#include <luna-service2++/handle.hpp>
#include "lunaservice_client.h"
#include "lunaservice_utils.h"

class AdapterAsm
{
public:
    AdapterAsm(LS::Handle *handle, std::string serviceName);
    ~AdapterAsm();
	bool listDevices();
    // subscribe callback
    void listDevicesCb(LSUtils::LunaResponse &response);

    static AdapterAsm* getInstance();

private:
    static AdapterAsm *_instance;
	bool mAsmStatusCheckStarted;
    std::vector<std::string> mDeviceUris;
    std::string mServiceName;
    LSUtils::PersistentSubscription mStatusSubscription;
    LSUtils::LunaClient mLunaClient;
    //LSMessageToken mCallToken;
	//LSMessageToken mServiceStatusCall;
	std::mutex mMutex;
};

#endif /*ADAPTOR_ASM_HPP_*/