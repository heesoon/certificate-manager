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

#ifndef JSON_SCHEMA_HPP_
#define JSON_SCHEMA_HPP_

/*
 * Note : The strings are generated online from Json object
 * https://www.jsonschema.net/
 * Any change in string should be taken care else schema validation
 * will fail
 */

const char *getKeyInfoSchema = "{ \
    \"type\": \"object\",
    \"title\": \"The root schema\", \
    \"required\": [ \
        \"filename\", \
        \"keysize\" \
    ], \
    \"properties\": { \
        \"filename\": { \
            \"type\": \"string\", \
            \"title\": \"The filename schema\", \
            \"default\": \"\", \
        }, \
        \"keysize\": { \
            \"type\": \"integer\", \
            \"title\": \"The keysize schema\", \
            \"default\": 0, \
        } \
    } \
}";


#endif /*JSON_SCHEMA_HPP_*/