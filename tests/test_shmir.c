/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Expose platform extensions such as mkdtemp before system headers. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#if defined(__APPLE__)
/* Darwin hides mkdtemp() under strict POSIX feature selection. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#else
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include "shmir/shmir.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
static int checks=0;
#define CHECK(expr) do{checks++;if(!(expr)){fprintf(stderr,"FAILED %s:%d: %s\n",__FILE__,__LINE__,#expr);exit(1);}}while(0)
static const char *password="correct horse battery staple";
int main(void){
 shmir_shares shares;CHECK(shmir_create(41216,37,82,&shares)==SHMIR_OK);
 int expected[]={41335,41618,42065,42676,43451};
 for(int i=0;i<5;i++){CHECK(shares.items[i].x==i+1);CHECK(shares.items[i].y==expected[i]);}
 CHECK(shmir_validate(&shares)==SHMIR_OK);CHECK(shmir_create(-1,1,1,&shares)==SHMIR_INVALID);
 CHECK(shmir_create(1,1,0,&shares)==SHMIR_INVALID);
 CHECK(shmir_create(41216,37,82,&shares)==SHMIR_OK);
 for(int mask=0;mask<32;mask++){
  shmir_share group[5];int n=0,secret=-1;
  for(int i=0;i<5;i++)if(mask&(1<<i))group[n++]=shares.items[i];
  if(n>=3){CHECK(shmir_recover(group,(size_t)n,&secret)==SHMIR_OK);CHECK(secret==41216);}
  else CHECK(shmir_recover(group,(size_t)n,&secret)==SHMIR_INVALID);
 }
 shmir_share duplicate[]={shares.items[0],shares.items[0],shares.items[2]};int recovered;
 CHECK(shmir_recover(duplicate,3,&recovered)==SHMIR_INVALID);
 for(int secret=0;secret<50021;secret+=1237){shmir_shares random;
  CHECK(shmir_split(secret,&random)==SHMIR_OK);
  CHECK(shmir_validate(&random)==SHMIR_OK);
  CHECK(shmir_recover(random.items,5,&recovered)==SHMIR_OK);
  CHECK(recovered==secret);
 }
 /* Original Python state_path():
    Path(os.environ.get("XDG_STATE_HOME", str(Path.home()/".local"/"state")))
    / "shamir-secret-sharing" / "shares.enc". */
 char state_path_buf[4096];
 CHECK(shmir_state_path(state_path_buf,sizeof state_path_buf,0)==SHMIR_OK);
 const char *xdg=getenv("XDG_STATE_HOME");
 if(xdg&&*xdg){char expected[4096];
   CHECK(snprintf(expected,sizeof expected,"%s/shamir-secret-sharing/shares.enc",xdg)>0);
   CHECK(strcmp(state_path_buf,expected)==0);
 }else{const char *home=getenv("HOME");CHECK(home&&*home);
   char expected[4096];
   CHECK(snprintf(expected,sizeof expected,"%s/.local/state/shamir-secret-sharing/shares.enc",home)>0);
   CHECK(strcmp(state_path_buf,expected)==0);
 }
 CHECK(shmir_state_path(state_path_buf,sizeof state_path_buf,1)==SHMIR_OK);
 CHECK(strstr(state_path_buf,"/shamir-secret-sharing/shares.json")!=NULL);
 /* macOS /tmp is a symlink to /private/tmp. The storage layer deliberately
    rejects symlink components for secure writes, so use the canonical path. */
 char tmp[]="/tmp/shmir-test-XXXXXX";CHECK(mkdtemp(tmp)!=NULL);
 char *canonical_tmp=realpath(tmp,NULL);CHECK(canonical_tmp!=NULL);
 char path[4096],legacy[4096],export_path[4096];
 CHECK(snprintf(path,sizeof path,"%s/child/shares.enc",canonical_tmp)>0);
 CHECK(snprintf(legacy,sizeof legacy,"%s/shares.json",canonical_tmp)>0);
 CHECK(snprintf(export_path,sizeof export_path,"%s/share-2.txt",canonical_tmp)>0);
 CHECK(shmir_save(&shares,password,path)==SHMIR_OK);
 struct stat st;CHECK(stat(path,&st)==0);CHECK((st.st_mode&0777)==0600);
 shmir_shares readback;CHECK(shmir_load(&readback,password,path)==SHMIR_OK);
 CHECK(memcmp(&shares,&readback,sizeof shares)==0);
 CHECK(shmir_load(&readback,"wrong password",path)==SHMIR_AUTH);
 FILE *f=fopen(path,"rb+");CHECK(f!=NULL);CHECK(fseek(f,-6,SEEK_END)==0);
 int ch=fgetc(f);CHECK(ch!=EOF);CHECK(fseek(f,-1,SEEK_CUR)==0);CHECK(fputc(ch=='A'?'B':'A',f)!=EOF);CHECK(fclose(f)==0);
 CHECK(shmir_load(&readback,password,path)!=SHMIR_OK);
 CHECK(shmir_save(&shares,password,path)==SHMIR_OK);
 CHECK(shmir_export(&shares,2,export_path)==SHMIR_OK);
 CHECK(shmir_export(&shares,2,export_path)==SHMIR_EXISTS);
 CHECK(stat(export_path,&st)==0);CHECK((st.st_mode&0777)==0600);
 CHECK(shmir_delete(path)==SHMIR_OK);CHECK(shmir_load(&readback,password,path)==SHMIR_NOT_FOUND);
 unlink(export_path);rmdir(strcat(strcpy(path,canonical_tmp),"/child"));rmdir(canonical_tmp);free(canonical_tmp);
 printf("PASS: %d assertions\n",checks);return 0;
}
