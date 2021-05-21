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

#ifndef CERTIFICATE_MANAGER_SERVICE_H_
#define CERTIFICATE_MANAGER_SERVICE_H_

/*-----------------------------------------------------------------------------
 (File Inclusions)
 ------------------------------------------------------------------------------*/
#include <memory>
#include <luna-service2/lunaservice.hpp>
#include <pbnjson.hpp>

class CertificateManager : public LS::Handle
{
private :
	using unique_ptr_mainLoop_t = std::unique_ptr<GMainLoop, void (*)(GMainLoop *)>;
	unique_ptr_mainLoop_t upGmainLoop = {g_main_loop_new(nullptr, false), g_main_loop_unref};

public :
	CertificateManager();
	CertificateManager(CertificateManager const&) = delete;
	CertificateManager(CertificateManager &&) = delete;
	CertificateManager& operator =(CertificateManager const&) = delete;
	CertificateManager& operator =(CertificateManager && ) = delete;

	bool generateKey(LSMessage &message);
	bool csr(LSMessage &message);
	bool sign(LSMessage &message);
	bool verify(LSMessage &message);
};

#endif /*CERTIFICATE_MANAGER_SERVICE_H_*/