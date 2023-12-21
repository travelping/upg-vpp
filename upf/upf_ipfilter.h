/*
 * upf_proxy.h - 3GPP TS 29.244 GTP-U UP plug-in header file
 *
 * Copyright (c) 2018,2019 Travelping GmbH
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
#ifndef __included_upf_ipfilter_h__
#define __included_upf_ipfilter_h__

#include "upf.h"

uword unformat_ipfilter (unformat_input_t *i, va_list *args);
u8 *format_ipfilter (u8 *s, va_list *args);

#endif
