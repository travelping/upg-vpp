/*
 * Copyright (c) 2024-2025 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef UPF_UPF_LIMITS_H_
#define UPF_UPF_LIMITS_H_

// Reference from open5g:
// https://github.com/open5gs/open5gs/blob/1182a99d041e3461b5493f2f800a434f41a9eee1/lib/pfcp/ogs-pfcp.h#L29-L33

#define UPF_LIMIT_MAX_ASSOCIATIONS 200
#define UPF_LIMIT_MAX_SMFSETS      200

// Limit total amount of sessions to 24 bits, so we have more opportunities for
// optimizations. This equals to 16.77 million sessions, what is
// unrealistic for any single VPP deployment from network performance and from
// failover perspectives. For safety limit this number rounded to 16 millions,
// so it could fit temporary objects.
#define UPF_LIMIT_MAX_SESSIONS 16000000

#endif // UPF_UPF_LIMITS_H_
