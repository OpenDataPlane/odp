# Copyright (c) 2014, Linaro Limited
# Copyright (c) 2014, Texas Instruments Incorporated
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

# MCSDK_CFLAGS should match flags used to build McSDK libraries

KS2_DEVICE ?= k2k
CSL_DEVICE = DEVICE_K2K

MCSDK_CFLAGS  = -D$(CSL_DEVICE) -D_GNU_SOURCE -D_LITTLE_ENDIAN
MCSDK_CFLAGS += -D__ARMv7 -D_VIRTUAL_ADDR_SUPPORT -DMAKEFILE_BUILD
MCSDK_CFLAGS += -DNWAL_ENABLE_SA

AM_CFLAGS  += $(MCSDK_CFLAGS)
AM_CFLAGS  += -I$(SDK_INSTALL_PATH)/usr/include
AM_LDFLAGS += -L$(SDK_INSTALL_PATH)/usr/lib
