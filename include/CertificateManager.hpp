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

#ifndef CERTIFICATE_MANAGER_SERVICE_HPP_
#define CERTIFICATE_MANAGER_SERVICE_HPP_

/*-----------------------------------------------------------------------------
 (File Inclusions)
 ------------------------------------------------------------------------------*/
#include <memory>
#include "lunaservice_utils.h"

class CertificateManager{

public :
	CertificateManager(LSUtils::LunaService &service);
	CertificateManager(CertificateManager const&) = delete;
	CertificateManager(CertificateManager &&) = delete;
	CertificateManager& operator =(CertificateManager const&) = delete;
	CertificateManager& operator =(CertificateManager && ) = delete;

	pbnjson::JValue generateKey(LSUtils::LunaRequest &request);
	pbnjson::JValue csr(LSUtils::LunaRequest &request);
	pbnjson::JValue sign(LSUtils::LunaRequest &request);
	pbnjson::JValue verify(LSUtils::LunaRequest &request);
};

#endif /*CERTIFICATE_MANAGER_SERVICE_HPP_*/