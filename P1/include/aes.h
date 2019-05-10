/*!
 * \file aes.h
 * \author Garrett Larsen
 * \date 2.10.2018
 * \version 0.1.0
 * \brief Project 1 (AES) interface for Computer Security
 *
 * \details Submit bug reports and feature requests via https://github.com/ASRL/CS-SYY-Zulu
 */

#ifndef LIB_AES_H
#define LIB_AES_H

#include <stdint.h>
#include <stddef.h>

/*!
 * \brief Initialize the cipher context
 *
 * \param[in] key the cipher key
 * \param[in] len the length of the cipher key
 * \return Returns 1 on success or -1 on failure
 * \note Supports 128b, 192b, and 256b keys
 */
int init (const uint8_t *key, const size_t len);

/*!
 * \brief Encrypt a block of data
 *
 * \param[in] in the block to be encrypted
 * \param[out] out the resulting encrypted block
 * \note Blocks must be 16B in length
 */
void encrypt (const uint8_t * in, uint8_t *out);

/*!
 * \brief Decrypt a block of data
 *
 * \param[in] in the block to be decrypted
 * \param[out] out the resulting decrypted block
 * \note Blocks must be 16B in length
 */
void decrypt (const uint8_t * in, uint8_t *out);

#endif