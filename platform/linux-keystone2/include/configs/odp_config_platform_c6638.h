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


/*
 * This is the typical configuration for TCI6638  (KeyStone 2, Linux ARM A15)
 *
 * Descriptors and PDSP communications memory must reside in contiguous and coherent DDR
 * (using CMA).
 *
 * On KeyStone2 QMSS regions do not need to be ordered.
 */
#ifndef ODP_CONFIG_PLATFORM_C6638_H_
#define ODP_CONFIG_PLATFORM_C6638_H_

/* Cores are here "EM cores" that are not necessarily tied to real "CPU cores" */
#define MY_EM_CORE_NUM               (4)           /* number of cores used by OpenEM */
#define MY_EM_INIT_CORE_IDX          (0)           /* core on which the init will be started */

/* Index of the QMSS PDSP that will be used by OpenEM, Linux use QMSS PDSP0 for accumulator */
#define MY_EM_SCHED_PDSP_IDX         (2)

/* Define if we are polling or waiting on event interrupts when dispatching events */
#define MY_EM_DISPATCH_MODE          (TI_EM_RH_POLL_MODE)

/*
 * Coherent contiguous memory used for PDSP <-> CPU communication
 * We use one page per slot and CORE_NUM + 2 slots
 */
#ifdef TI_EM_USE_MSM
#define MY_EM_PDSP_COMM_MEM_BASE     (0x0c000000) /* MSM */
#else
#define MY_EM_PDSP_COMM_MEM_BASE     (0x0)         /* use DDR from CMA (contiguous & coherent)*/
#endif
#define MY_EM_PDSP_COMM_MEM_VBASE    (0x0)         /* dynamic mapping */
#define MY_EM_PDSP_COMM_MEM_SIZE     (0x00010000)  /* allowing 16 slots */
#define MY_EM_PDSP_COMM_MEM_OFFSET   (0x0)         /* no offset */

/*
 * Base physical address for event descriptors.
 * In the future in will be managed by Linux or platform resource manager.
 */
#ifdef TI_EM_USE_MSM
#define TI_ODP_PUBLIC_DESC_BASE       (0x0c100000)  /* MSM */
#define TI_ODP_PUBLIC_DESC_VBASE      (0x0)         /* dynamic mapping */
#define TI_ODP_PUBLIC_DESC_OFFSET     (0x0)         /* no offset, QMSS/PDSP mapping equal to CPU mapping */
#else /* TI_EM_USE_MSM */
#define TI_ODP_PUBLIC_DESC_BASE       (0x0)         /* use DDR from CMA (contiguous & coherent)*/
#define TI_ODP_PUBLIC_DESC_VBASE      (0x0)         /* dynamic mapping */
#define TI_ODP_PUBLIC_DESC_OFFSET     (0x0)         /* no offset, QMSS/PDSP mapping equal to CPU mapping */
#endif /* TI_EM_USE_MSM */

#define TI_ODP_PUBLIC_REGION_IDX      (1)           /* Linux uses 12 & 13 on ARM, set in DTS */
#define TI_ODP_PRIVATE_REGION_IDX     (2)
#define TI_ODP_PUBLIC_START_DESC_IDX  (0)           /* start index for desc (Linux starts at 0x4000, set in DTS) */
#define TI_ODP_PRIVATE_START_DESC_IDX (-1)          /* Automatically computed */

#define TI_ODP_PRIVATE_DESC_BASE      (TI_EM_PDSPSH_DRAM)      /* use PDSP data RAM */
#define TI_ODP_PRIVATE_DESC_OFFSET    (TI_EM_PDSP_DRAM_OFFSET) /* offset between CPU and QMSS/PDSP mapping */
#define TI_ODP_PRIVATE_DESC_VBASE     (0x0)                    /* dynamic mapping */

/*
 * For the time being, free queues that can be used from user application are
 * harcoded here. In the future it will be provided by platform resource manager.
 */
#define TI_ODP_PUBLIC_QUEUE_BASE_IDX	(QMSS_GENERAL_PURPOSE_USER_QUEUE_BASE)
#define TI_ODP_FREE_QUEUE_BASE_IDX	(TI_ODP_PUBLIC_QUEUE_BASE_IDX + ODP_CONFIG_QUEUES)
#define MY_EM_PRIVATE_FREE_QUEUE_IDX	(TI_ODP_FREE_QUEUE_BASE_IDX + ODP_CONFIG_BUFFER_POOLS)
#define MY_EM_SCHED_QUEUE_IDX		(MY_EM_PRIVATE_FREE_QUEUE_IDX + 2)

#endif /* ODP_CONFIG_PLATFORM_C6638_H_ */
