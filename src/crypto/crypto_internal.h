/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef SHMIR_CRYPTO_INTERNAL_H
#define SHMIR_CRYPTO_INTERNAL_H
#include <stddef.h>
#include <stdint.h>
/* libargon2 public C ABI, declared here to accommodate runtime-only distributions. */
int argon2id_hash_raw(uint32_t t_cost,uint32_t m_cost,uint32_t parallelism,
 const void *pwd,size_t pwdlen,const void *salt,size_t saltlen,void *hash,size_t hashlen);
int shmir_derive(const char *password,const unsigned char salt[16],int time,int mem,int parallel,unsigned char key[32]);
int shmir_seal(const unsigned char key[32],const unsigned char nonce[12],const unsigned char *aad,int aadlen,
 const unsigned char *plain,int plainlen,unsigned char *out,int *outlen);
int shmir_open(const unsigned char key[32],const unsigned char nonce[12],const unsigned char *aad,int aadlen,
 const unsigned char *cipher,int cipherlen,unsigned char *out,int *outlen);
#endif
