/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP errno API
 */

#ifndef ODP_ERRNO_H_
#define ODP_ERRNO_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_errno ODP ERRNO
 *  @{
 */

/**
* Return latest ODP errno
*
* @return ODP errno
* @retval 0 No error
*/
int odp_errno(void);

/**
* Set ODP errno to zero
*/
void odp_errno_zero(void);

/**
* Print ODP errno
*
* Interprets the value of ODP errno as an error message, and prints it,
* optionally preceding it with the custom message specified in str.
*
* @param str NULL, or pointer to the string to be appended
*/
void odp_errno_print(const char *str);

/**
* Error message string
*
* Interprets the value of ODP errno, generating a string with a
* message that describes the error.
* It uses the system definition of errno.
*
* @param errnum	Error code
*
* @retval Pointer to the string
*/
const char *odp_errno_str(int errnum);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
