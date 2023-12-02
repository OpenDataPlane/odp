/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#ifndef ODP_MODEL_READ_H_
#define ODP_MODEL_READ_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/**
 * Read model binaries from model file
 *
 * @param file_name     The name of model file
 * @param model_param   Model parameter where model content and size are read to
 *
 * @retval      0 on success
 * @retval      < 0 on failure
 */
int read_model_from_file(const char *file_name, odp_ml_model_param_t *model_param);

#ifdef __cplusplus
}
#endif

#endif
