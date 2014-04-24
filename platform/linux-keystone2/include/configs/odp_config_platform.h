/*
 * Copyright (c) 2012, Texas Instruments Incorporated - http://www.ti.com/
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *       * Neither the name of Texas Instruments Incorporated nor the
 *         names of its contributors may be used to endorse or promote products
 *         derived from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
 *   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef ODP_CONFIG_PLATFORM_H_
#define ODP_CONFIG_PLATFORM_H_

/* #include <openem/event_machine.h> */
#if defined(TI_EM_C6678)
#include <configs/odp_config_platform_c6678.h>
#elif defined(TI_EM_C6614)
#include <configs/odp_config_platform_c6614.h>
#elif defined(TI_EM_C6638)
#include <configs/odp_config_platform_c6638.h>
#else
#error "platform not defined or unsupported!"
#endif

#define TI_ODP_PUBLIC_DESC_NUM		(4096u)
#define TI_ODP_REGION_NUM		(2)  /* local regions are not used on Linux */

#define MY_EM_DEVICE_ID              (0)
#define MY_EM_PROCESS_ID             (0)

/*
 * Queue, pool and event definitions
 */
#define MY_EM_PROC_QUEUE_NUM         (32)
#define MY_EM_PROC_QUEUE_TYPE        (EM_QUEUE_TYPE_PARALLEL)
#define MY_EM_PROC_EVENT_TYPE        (TI_EM_EVENT_TYPE_PRELOAD_OFF)

#endif /* ODP_CONFIG_PLATFORM_H_ */
