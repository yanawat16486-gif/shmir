/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "shmir/shmir.h"
#include <openssl/rand.h>
static int modp(int64_t a) { int64_t r=a%SHMIR_PRIME; return (int)(r<0?r+SHMIR_PRIME:r); }
static int inverse(int a) {
 int64_t t=0, newt=1, r=SHMIR_PRIME, newr=modp(a);
 while(newr){ int64_t q=r/newr, tmp=t-q*newt; t=newt; newt=tmp; tmp=r-q*newr; r=newr; newr=tmp; }
 return r==1?modp(t):-1;
}
shmir_status shmir_create(int secret,int a1,int a2,shmir_shares *out){
 if(!out||secret<0||secret>=SHMIR_PRIME||a1<0||a1>=SHMIR_PRIME||a2<=0||a2>=SHMIR_PRIME) return SHMIR_INVALID;
 for(int x=1;x<=SHMIR_N;x++){out->items[x-1]=(shmir_share){x,modp((int64_t)secret+(int64_t)a1*x+(int64_t)a2*x*x)};}
 return SHMIR_OK;
}
static shmir_status random_field(int nonzero,int *result){
 uint32_t v;
 const uint64_t limit=(UINT64_C(1)<<32)-((UINT64_C(1)<<32)%SHMIR_PRIME);
 if(!result)return SHMIR_INVALID;
 do {if(RAND_bytes((unsigned char*)&v,sizeof v)!=1)return SHMIR_CRYPTO;}while(v>=limit);
 *result=(int)(v%SHMIR_PRIME);
 if(nonzero&&*result==0)return random_field(nonzero,result);
 return SHMIR_OK;
}
shmir_status shmir_split(int secret,shmir_shares *out){
 if(!out||secret<0||secret>=SHMIR_PRIME)return SHMIR_INVALID;
 int a,b; if(random_field(0,&a)||random_field(1,&b))return SHMIR_CRYPTO;
 return shmir_create(secret,a,b,out);
}
shmir_status shmir_recover(const shmir_share *in,size_t n,int *secret){
 if(!in||!secret||n<SHMIR_K||n>SHMIR_N)return SHMIR_INVALID;
 unsigned seen=0;
 for(size_t i=0;i<n;i++){
  if(in[i].x<1||in[i].x>SHMIR_N||in[i].y<0||in[i].y>=SHMIR_PRIME|| (seen&(1u<<in[i].x)))return SHMIR_INVALID;
  seen|=1u<<in[i].x;
 }
 int result=0;
 for(size_t i=0;i<n;i++){
  int num=1,den=1;
  for(size_t j=0;j<n;j++) if(i!=j){num=modp((int64_t)num*(-in[j].x));den=modp((int64_t)den*(in[i].x-in[j].x));}
  int inv=inverse(den); if(inv<0)return SHMIR_INVALID;
  result=modp((int64_t)result+(int64_t)in[i].y*num*inv);
 }
 *secret=result;return SHMIR_OK;
}
shmir_status shmir_validate(const shmir_shares *shares){
 if(!shares)return SHMIR_INVALID;
 int secret; if(shmir_recover(shares->items,3,&secret))return SHMIR_INVALID;
 unsigned seen=0;
 for(int i=0;i<SHMIR_N;i++){
  int x=shares->items[i].x;
  if(x<1||x>SHMIR_N||(seen&(1u<<x)))return SHMIR_INVALID;
  seen|=1u<<x;
 }
 for(int a=0;a<3;a++) for(int b=a+1;b<4;b++) for(int c=b+1;c<5;c++){
  shmir_share group[]={shares->items[a],shares->items[b],shares->items[c]};int recovered;
  if(shmir_recover(group,3,&recovered)||recovered!=secret)return SHMIR_INVALID;
 }
 return SHMIR_OK;
}
const char *shmir_error(shmir_status s){
 switch(s){case SHMIR_OK:return "ok";case SHMIR_INVALID:return "invalid shares/arguments";
 case SHMIR_CRYPTO:return "cryptography failure";case SHMIR_IO:return "I/O failure";
 case SHMIR_AUTH:return "wrong password or tampered ciphertext";
 case SHMIR_FORMAT:return "unsupported/corrupt file format";case SHMIR_NOT_FOUND:return "not found";
 case SHMIR_EXISTS:return "file exists";default:return "unknown";}
}
