# Copyright (c) 2008-2018 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 2.8.7)
project(com.webos.service.certificatemanager)

include(webOS/webOS)

webos_modules_init(1 0 0)
webos_component(1 0 0)

#webos_add_compiler_flags(ALL -DMOJ_LINUX -std=c++11 -fno-exceptions -Wall -Werror)
webos_add_compiler_flags(ALL -std=c++11 -Wall)

add_subdirectory(src)
