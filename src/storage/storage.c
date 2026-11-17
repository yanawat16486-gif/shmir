/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "shmir/shmir.h"
#include "../crypto/crypto_internal.h"
#include <json-c/json.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#define MAX_STATE 16384
static json_object *get(json_object *o,const char *k){json_object *v=NULL;return json_object_object_get_ex(o,k,&v)?v:NULL;}
static int json_int(json_object *o,int *v){if(!o||json_object_get_type(o)!=json_type_int)return 0;int64_t n=json_object_get_int64(o);if(n<INT_MIN||n>INT_MAX)return 0;*v=(int)n;return 1;}
static int field_int(json_object *o,const char *k,int *v){return json_int(get(o,k),v);}
static int field_string(json_object *o,const char *k,const char *s){json_object *v=get(o,k);return v&&json_object_get_type(v)==json_type_string&&!strcmp(json_object_get_string(v),s);}
static char *b64(const unsigned char *buf,int n){char *s=malloc((size_t)(4*((n+2)/3)+1));if(s)EVP_EncodeBlock((unsigned char*)s,buf,n);return s;}
static int unb64(json_object *o,unsigned char *out,size_t cap,int *length){
 if(!o||json_object_get_type(o)!=json_type_string)return 0;
 const char *s=json_object_get_string(o);size_t len=strlen(s);
 if(len==0||len%4||len>4*((cap+2)/3)+4)return 0;
 size_t padding=(size_t)(s[len-1]=='=')+(size_t)(len>1&&s[len-2]=='=');
 if(len/4*3-padding>cap)return 0;
 /* Python uses base64.b64decode(validate=True): accept only alphabet, padding at end. */
 for(size_t i=0;i<len-padding;i++)if(!((s[i]>='A'&&s[i]<='Z')||(s[i]>='a'&&s[i]<='z')||(s[i]>='0'&&s[i]<='9')||s[i]=='+'||s[i]=='/'))return 0;
 for(size_t i=len-padding;i<len;i++)if(s[i]!='=')return 0;
 int n=EVP_DecodeBlock(out,(const unsigned char*)s,(int)len);if(n<0)return 0;
 *length=n-(int)padding;return 1;
}
static int parse_shares(json_object *root,shmir_shares *out,int is_legacy){
 int prime,version;
 if(!field_int(root,"prime",&prime)||prime!=SHMIR_PRIME)return 0;
 if(is_legacy&&(!field_int(root,"version",&version)||version!=1))return 0;
 json_object *arr=get(root,"shares");if(!arr||json_object_get_type(arr)!=json_type_array||json_object_array_length(arr)!=SHMIR_N)return 0;
 for(int i=0;i<SHMIR_N;i++){
  json_object *pair=json_object_array_get_idx(arr,(size_t)i);
  if(!pair||json_object_get_type(pair)!=json_type_array||json_object_array_length(pair)!=2||
     !json_int(json_object_array_get_idx(pair,0),&out->items[i].x)||!json_int(json_object_array_get_idx(pair,1),&out->items[i].y))return 0;
 }
 return shmir_validate(out)==SHMIR_OK;
}
static json_object *shares_json(const shmir_shares *shares){
 json_object *root=json_object_new_object(),*arr=json_object_new_array();
 json_object_object_add(root,"prime",json_object_new_int(SHMIR_PRIME));
 for(int x=1;x<=5;x++){json_object *pair=json_object_new_array();
  for(int j=0;j<5;j++)if(shares->items[j].x==x){json_object_array_add(pair,json_object_new_int(x));json_object_array_add(pair,json_object_new_int(shares->items[j].y));break;}
  json_object_array_add(arr,pair);
 }
 json_object_object_add(root,"shares",arr);return root;
}
static int read_file(const char *path,char **buf,size_t *len){
 int fd=open(path,O_RDONLY|O_NOFOLLOW);if(fd<0)return 0;
 struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<0||st.st_size>MAX_STATE){close(fd);return 0;}
 char *s=calloc((size_t)st.st_size+1,1);if(!s){close(fd);return 0;}
 size_t n=0;while(n<(size_t)st.st_size){ssize_t r=read(fd,s+n,(size_t)st.st_size-n);if(r<=0){free(s);close(fd);return 0;}n+=(size_t)r;}
 close(fd);*buf=s;*len=n;return 1;
}
static int secure_dir(const char *path){
 char *s=strdup(path);if(!s)return 0;char *slash=strrchr(s,'/');if(!slash){free(s);return 0;}
 *slash=0;int ok=1;
 for(char *p=s+1;;p++) if(*p=='/'||*p=='\0'){
   char end=*p;*p=0;struct stat st;
   if(lstat(s,&st)==-1){if(errno!=ENOENT||mkdir(s,0700)){ok=0;break;}}
   else if(!S_ISDIR(st.st_mode)){ok=0;break;}
   if(!end)break;
   *p=end;
 }
 /* Apply restrictive mode to the shmir state directory, not ancestors. */
 if(ok){struct stat st;if(lstat(s,&st)||!S_ISDIR(st.st_mode)||chmod(s,0700))ok=0;}
 free(s);return ok;
}
static shmir_status atomic_write(const char *path,const char *data,size_t n){
 if(!secure_dir(path))return SHMIR_IO;
 struct stat st;if(lstat(path,&st)==0&&S_ISLNK(st.st_mode))return SHMIR_IO;
 if(lstat(path,&st)!=0&&errno!=ENOENT)return SHMIR_IO;
 char *tmp=malloc(strlen(path)+20);if(!tmp)return SHMIR_IO;
 sprintf(tmp,"%s.tmp-XXXXXX",path);int fd=mkstemp(tmp);if(fd<0){free(tmp);return SHMIR_IO;}
 int ok=(fchmod(fd,0600)==0);size_t offset=0;
 while(ok&&offset<n){ssize_t k=write(fd,data+offset,n-offset);if(k<=0)ok=0;else offset+=(size_t)k;}
 if(ok&&fsync(fd))ok=0;
 if(close(fd))ok=0;
 if(ok&&rename(tmp,path))ok=0;
 if(!ok)unlink(tmp);
 else {char *dir=strdup(path);if(dir){char *slash=strrchr(dir,'/');if(slash){*slash=0;int d=open(dir,O_RDONLY);if(d>=0){(void)fsync(d);close(d);}}free(dir);}}
 free(tmp);return ok?SHMIR_OK:SHMIR_IO;
}
shmir_status shmir_save(const shmir_shares *shares,const char *password,const char *path){
 if(shmir_validate(shares)||!password||!*password||!path)return SHMIR_INVALID;
 unsigned char salt[16],nonce[12],key[32]={0},cipher[2048];int clen=0;char *bs=NULL,*bn=NULL,*bc=NULL;
 json_object *plain=NULL,*env=NULL,*kdf=NULL;shmir_status status=SHMIR_CRYPTO;
 if(RAND_bytes(salt,16)!=1||RAND_bytes(nonce,12)!=1)goto done;
 if(!shmir_derive(password,salt,3,65536,2,key))goto done;
 bs=b64(salt,16);bn=b64(nonce,12);if(!bs||!bn)goto done;
 /* AAD must exactly equal Python json.dumps(header,sort_keys=True,separators=(',',':')). */
 char aad[512];int aadlen=snprintf(aad,sizeof aad,"{\"cipher\":\"AES-256-GCM\",\"kdf\":{\"memory_kib\":65536,\"name\":\"argon2id\",\"parallelism\":2,\"time\":3},\"nonce\":\"%s\",\"salt\":\"%s\",\"version\":2}",bn,bs);
 if(aadlen<0||(size_t)aadlen>=sizeof aad)goto done;
 plain=shares_json(shares);const char *txt=json_object_to_json_string_ext(plain,JSON_C_TO_STRING_PLAIN);
 if(strlen(txt)>sizeof cipher-16)goto done;
 if(!shmir_seal(key,nonce,(unsigned char*)aad,aadlen,(unsigned char*)txt,(int)strlen(txt),cipher,&clen))goto done;
 bc=b64(cipher,clen);if(!bc)goto done;
 env=json_object_new_object();kdf=json_object_new_object();
 json_object_object_add(env,"version",json_object_new_int(2));json_object_object_add(env,"cipher",json_object_new_string("AES-256-GCM"));
 json_object_object_add(kdf,"name",json_object_new_string("argon2id"));json_object_object_add(kdf,"time",json_object_new_int(3));json_object_object_add(kdf,"memory_kib",json_object_new_int(65536));json_object_object_add(kdf,"parallelism",json_object_new_int(2));
 json_object_object_add(env,"kdf",kdf);kdf=NULL;
 json_object_object_add(env,"salt",json_object_new_string(bs));json_object_object_add(env,"nonce",json_object_new_string(bn));json_object_object_add(env,"ciphertext",json_object_new_string(bc));
 txt=json_object_to_json_string_ext(env,JSON_C_TO_STRING_PLAIN);status=atomic_write(path,txt,strlen(txt));
 done:OPENSSL_cleanse(key,sizeof key);OPENSSL_cleanse(cipher,sizeof cipher);free(bs);free(bn);free(bc);
 if(plain)json_object_put(plain);
 if(env)json_object_put(env);
 if(kdf)json_object_put(kdf);
 return status;
}
shmir_status shmir_load(shmir_shares *shares,const char *password,const char *path){
 if(!shares||!password||!path)return SHMIR_INVALID;
 if(access(path,F_OK))return errno==ENOENT?SHMIR_NOT_FOUND:SHMIR_IO;
 char *buf=NULL;size_t len=0;if(!read_file(path,&buf,&len))return SHMIR_IO;
 json_object *env=json_tokener_parse(buf),*kdf=NULL,*plain=NULL;free(buf);
 unsigned char salt[64],nonce[64],cipher[8192],key[32]={0},out[8192]={0};int sl=0,nl=0,cl=0,ol=0,t=0,m=0,p=0,ver=0;
 shmir_status status=SHMIR_FORMAT;char *bs=NULL,*bn=NULL;
 if(!env||json_object_get_type(env)!=json_type_object||!field_int(env,"version",&ver)||ver!=2||!field_string(env,"cipher","AES-256-GCM"))goto done;
 kdf=get(env,"kdf");if(!kdf||json_object_get_type(kdf)!=json_type_object||!field_string(kdf,"name","argon2id")||!field_int(kdf,"time",&t)||!field_int(kdf,"memory_kib",&m)||!field_int(kdf,"parallelism",&p)||t<1||t>10||m<8192||m>262144||p<1||p>8)goto done;
 if(!unb64(get(env,"salt"),salt,sizeof salt,&sl)||sl!=16||!unb64(get(env,"nonce"),nonce,sizeof nonce,&nl)||nl!=12||!unb64(get(env,"ciphertext"),cipher,sizeof cipher,&cl))goto done;
 bs=b64(salt,16);bn=b64(nonce,12);if(!bs||!bn)goto done;
 char aad[512];int aadlen=snprintf(aad,sizeof aad,"{\"cipher\":\"AES-256-GCM\",\"kdf\":{\"memory_kib\":%d,\"name\":\"argon2id\",\"parallelism\":%d,\"time\":%d},\"nonce\":\"%s\",\"salt\":\"%s\",\"version\":2}",m,p,t,bn,bs);
 if(aadlen<0||(size_t)aadlen>=sizeof aad)goto done;
 if(!shmir_derive(password,salt,t,m,p,key)){status=SHMIR_CRYPTO;goto done;}
 if(!shmir_open(key,nonce,(unsigned char*)aad,aadlen,cipher,cl,out,&ol)){status=SHMIR_AUTH;goto done;}
 out[ol]=0;plain=json_tokener_parse((char*)out);
 if(!plain||json_object_get_type(plain)!=json_type_object||!parse_shares(plain,shares,0))goto done;
 status=SHMIR_OK;
 done:OPENSSL_cleanse(key,sizeof key);OPENSSL_cleanse(out,sizeof out);OPENSSL_cleanse(cipher,sizeof cipher);
 free(bs);free(bn);if(env)json_object_put(env);if(plain)json_object_put(plain);return status;
}
shmir_status shmir_load_legacy(shmir_shares *shares,const char *path){
 if(!shares||!path)return SHMIR_INVALID;
 if(access(path,F_OK))return errno==ENOENT?SHMIR_NOT_FOUND:SHMIR_IO;
 char *buf=NULL;size_t len;if(!read_file(path,&buf,&len))return SHMIR_IO;
 json_object *root=json_tokener_parse(buf);free(buf);if(!root)return SHMIR_FORMAT;
 int ok=parse_shares(root,shares,1);json_object_put(root);return ok?SHMIR_OK:SHMIR_FORMAT;
}
shmir_status shmir_export(const shmir_shares *shares,int holder,const char *path){
 if(shmir_validate(shares)||holder<1||holder>5||!path)return SHMIR_INVALID;
 int y=-1;for(int i=0;i<5;i++)if(shares->items[i].x==holder)y=shares->items[i].y;
 char buf[160];int n=snprintf(buf,sizeof buf,"SHAMIR SHARE v1\nholder=%d\nvalue=%d\nprime=50021\nthreshold=3\ntotal=5\n",holder,y);
 int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
 if(fd<0)return errno==EEXIST?SHMIR_EXISTS:SHMIR_IO;
 int ok=(fchmod(fd,0600)==0);int offset=0;
 while(ok&&offset<n){ssize_t k=write(fd,buf+offset,(size_t)(n-offset));if(k<=0)ok=0;else offset+=(int)k;}
 if(ok&&fsync(fd))ok=0;
 if(close(fd))ok=0;
 if(!ok)unlink(path);
 return ok?SHMIR_OK:SHMIR_IO;
}
shmir_status shmir_delete(const char *path){if(!path)return SHMIR_INVALID;return unlink(path)==0?SHMIR_OK:(errno==ENOENT?SHMIR_NOT_FOUND:SHMIR_IO);}
