/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "crypto_internal.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>
int shmir_derive(const char *password,const unsigned char salt[16],int time,int mem,int parallel,unsigned char key[32]){
 if(!password||!*password||time<1||time>10||mem<8192||mem>262144||parallel<1||parallel>8)return 0;
 return argon2id_hash_raw((uint32_t)time,(uint32_t)mem,(uint32_t)parallel,password,strlen(password),salt,16,key,32)==0;
}
int shmir_seal(const unsigned char key[32],const unsigned char nonce[12],const unsigned char *aad,int aadlen,
 const unsigned char *plain,int plainlen,unsigned char *out,int *outlen){
 EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();int n=0,m=0,ok=0;
 if(!c)return 0;
 if(EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),NULL,key,nonce)!=1)goto done;
 if(EVP_EncryptUpdate(c,NULL,&n,aad,aadlen)!=1)goto done;
 if(EVP_EncryptUpdate(c,out,&n,plain,plainlen)!=1)goto done;
 if(EVP_EncryptFinal_ex(c,out+n,&m)!=1)goto done;
 *outlen=n+m;
 if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,out+*outlen)!=1)goto done;
 *outlen+=16;ok=1;
 done:EVP_CIPHER_CTX_free(c);return ok;
}
int shmir_open(const unsigned char key[32],const unsigned char nonce[12],const unsigned char *aad,int aadlen,
 const unsigned char *cipher,int cipherlen,unsigned char *out,int *outlen){
 if(cipherlen<16)return 0;
 EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();int n=0,m=0,ok=0;
 if(!c)return 0;
 if(EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),NULL,key,nonce)!=1)goto done;
 if(EVP_DecryptUpdate(c,NULL,&n,aad,aadlen)!=1)goto done;
 if(EVP_DecryptUpdate(c,out,&n,cipher,cipherlen-16)!=1)goto done;
 if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,(void*)(cipher+cipherlen-16))!=1)goto done;
 if(EVP_DecryptFinal_ex(c,out+n,&m)!=1)goto done;
 *outlen=n+m;ok=1;
 done:EVP_CIPHER_CTX_free(c);return ok;
}
