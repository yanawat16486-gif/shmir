/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#define _POSIX_C_SOURCE 200809L
#include "shmir/shmir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>
#include <limits.h>
static int line(char *buf,size_t cap,const char *prompt){
 fputs(prompt,stdout);fflush(stdout);
 if(!fgets(buf,(int)cap,stdin))return 0;
 size_t n=strlen(buf);if(n&&buf[n-1]=='\n')buf[n-1]=0;
 else if(n==cap-1){int ch;while((ch=getchar())!='\n'&&ch!=EOF){};return 0;}
 return 1;
}
static int password(char *buf,size_t cap,const char *prompt){
 struct termios old,now;int tty=isatty(STDIN_FILENO),changed=0;
 if(tty&&tcgetattr(STDIN_FILENO,&old)==0){now=old;now.c_lflag&=(tcflag_t)~ECHO;if(tcsetattr(STDIN_FILENO,TCSANOW,&now)==0)changed=1;}
 int ok=line(buf,cap,prompt);
 if(changed){tcsetattr(STDIN_FILENO,TCSANOW,&old);puts("");}
 return ok;
}
static void wipe(char *s,size_t n){volatile char *p=(volatile char *)s;while(n--)*p++=0;}
static int new_password(char *out,size_t cap){
 char confirm[512];
 for(;;){if(!password(out,cap,"New password (min 12, /cancel to stop): "))return 0;
  if(!strcmp(out,"/cancel")){wipe(out,cap);return 0;}
  if(strlen(out)<12){puts("Password too short.");continue;}
  if(!password(confirm,sizeof confirm,"Confirm: "))return 0;
  int ok=!strcmp(out,confirm);wipe(confirm,sizeof confirm);
  if(ok)return 1;puts("Passwords do not match.");
 }
}
static int integer(const char *s,int lo,int hi,int *out){
 if(!s||!*s)return 0;char *end;long n=strtol(s,&end,10);
 while(isspace((unsigned char)*end))end++;
 if(*end||n<lo||n>hi)return 0;*out=(int)n;return 1;
}
static void show(const shmir_shares *shares){for(int i=0;i<5;i++)printf("holder=%d value=%d\n",shares->items[i].x,shares->items[i].y);}
static void demo(void){
 shmir_shares shares;shmir_create(41216,37,82,&shares);
 puts("Shamir 3-of-5 demo: f(x) = (41216 + 37x + 82x^2) mod 50021");show(&shares);
 for(int mask=0;mask<32;mask++){shmir_share list[5];int n=0,secret;
  for(int j=0;j<5;j++)if(mask&(1<<j))list[n++]=shares.items[j];
  if(n>=3){shmir_status s=shmir_recover(list,(size_t)n,&secret);if(s||secret!=41216){puts("DEMO FAILED");return;}}
 }
 puts("All 3/4/5-share combinations recover 41216 (26 combinations).");
}
static void help(void){puts("shmir - Shamir's Secret Sharing 3-of-5 (C17)\n"
 "Usage: shmir [--help|help|--demo|--test|--setup|--no-alt-screen]\n"
 "  --demo            Fixed mathematical example\n"
 "  --setup           Replace old state with a new password and secret (interactive)\n"
 "  --test            Run unit tests via CTest (use ctest --test-dir build)\n"
 "  --no-alt-screen   Keep text in current terminal\n"
 "  (no args)         Interactive encrypted-state CLI");}
/* Explicit clean initialization.  Save and verify new encrypted state before
   removing the legacy plaintext state. Never generate or print a password. */
static int clean_setup(void){
 char state[4096],legacy[4096],pwd[512]={0},buf[128];
 if(!isatty(STDIN_FILENO)||!isatty(STDOUT_FILENO)){
  fputs("Clean setup requires an interactive terminal.\n",stderr);return 1;
 }
 if(shmir_state_path(state,sizeof state,0)||shmir_state_path(legacy,sizeof legacy,1)){
  fputs("Cannot resolve state paths.\n",stderr);return 1;
 }
 printf("Clean shmir initialization\nState: %s\n",state);
 puts("WARNING: a successful setup REPLACES existing encrypted shares and deletes legacy shares.json.");
 puts("Python and C versions use the SAME state location. This cannot be undone.");
 if(!line(buf,sizeof buf,"Type RESET SHMIR to continue: ")||strcmp(buf,"RESET SHMIR")){
  puts("Cancelled; existing state unchanged.");return 1;
 }
 if(!line(buf,sizeof buf,"New secret number (0-50020): "))return 1;
 int secret;if(!integer(buf,0,50020,&secret)){fputs("Invalid secret.\n",stderr);return 1;}
 if(!new_password(pwd,sizeof pwd)){puts("Cancelled; existing state unchanged.");wipe(pwd,sizeof pwd);return 1;}
 shmir_shares shares,check;int result=1;
 if(shmir_split(secret,&shares)!=SHMIR_OK){fputs("Random generation failed.\n",stderr);goto done;}
 shmir_status status=shmir_save(&shares,pwd,state);
 if(status!=SHMIR_OK){fprintf(stderr,"Could not save new state: %s\n",shmir_error(status));goto done;}
 status=shmir_load(&check,pwd,state);
 if(status!=SHMIR_OK||memcmp(&shares,&check,sizeof shares)!=0){
  fputs("WARNING: saved state verification failed. Do not delete legacy data.\n",stderr);goto done;
 }
 if(unlink(legacy)!=0&&access(legacy,F_OK)==0){
  fputs("WARNING: new state saved but legacy shares.json could not be removed.\n",stderr);goto done;
 }
 puts("New encrypted state created, verified, and old plaintext state removed.");
 result=0;
 done:wipe(pwd,sizeof pwd);return result;
}
static int select_holders(const shmir_shares *shares){
 char input[128];if(!line(input,sizeof input,"Enter holder numbers, e.g. 1 3 5: "))return 0;
 shmir_share chosen[5];int seen=0,n=0;char *save=NULL;
 for(char *part=strtok_r(input," ,\t",&save);part;part=strtok_r(NULL," ,\t",&save)){
  int x;if(!integer(part,1,5,&x)||(seen&(1<<x))||n==5){puts("Invalid holder list.");return 1;}
  seen|=1<<x;for(int i=0;i<5;i++)if(shares->items[i].x==x){chosen[n++]=shares->items[i];break;}
 }
 int result;if(shmir_recover(chosen,(size_t)n,&result))puts("Need 3 to 5 unique holders.");else printf("Recovered secret: %d\n",result);
 return 1;
}
static int manual_recover(void){
 char buf[128];int n;if(!line(buf,sizeof buf,"Number of shares (3-5): ")||!integer(buf,3,5,&n)){puts("Invalid count");return 1;}
 shmir_share chosen[5];for(int i=0;i<n;i++){
  if(!line(buf,sizeof buf,"Enter x y: "))return 0;
  int x,y;char extra;if(sscanf(buf,"%d %d %c",&x,&y,&extra)!=2){puts("Invalid pair");return 1;}
  chosen[i]=(shmir_share){x,y};
 }
 int secret;shmir_status s=shmir_recover(chosen,(size_t)n,&secret);
 if(s)printf("Recover failed: %s\n",shmir_error(s));else printf("Recovered secret: %d\n",secret);
 return 1;
}
static void interactive(void){
 char state[4096],legacy[4096],pwd[512]={0},buf[4096];shmir_shares shares;int loaded=0,has_password=0;
 if(shmir_state_path(state,sizeof state,0)||shmir_state_path(legacy,sizeof legacy,1)){puts("Cannot resolve state directory");return;}
 printf("shmir 3-of-5 Phase 2 (C17)\nState: %s\n",state);
 if(access(state,F_OK)==0){
  int ok=0;
  for(int i=0;i<3;i++){
   if(!password(pwd,sizeof pwd,"Unlock password: "))goto cleanup;
   shmir_status s=shmir_load(&shares,pwd,state);
   if(s==SHMIR_OK){ok=1;break;}
   printf("Unlock failed (%d/3): %s\n",i+1,shmir_error(s));wipe(pwd,sizeof pwd);
  }
  if(!ok){puts("Cannot unlock state; existing data left untouched.");goto cleanup;}
  loaded=has_password=1;
 }else if(access(legacy,F_OK)==0){
  puts("Found plaintext Phase 1 shares.json. Migration requires explicit YES.");
  if(!line(buf,sizeof buf,"Migrate to encrypted state? YES: ")||strcmp(buf,"YES"))goto cleanup;
  shmir_status s=shmir_load_legacy(&shares,legacy);if(s){printf("Invalid legacy file: %s\n",shmir_error(s));goto cleanup;}
  if(!new_password(pwd,sizeof pwd))goto cleanup;
  s=shmir_save(&shares,pwd,state);
  if(s){printf("Migration failed: %s\n",shmir_error(s));goto cleanup;}
  shmir_shares check;if(shmir_load(&check,pwd,state)!=SHMIR_OK){puts("Migration verification failed; legacy preserved.");goto cleanup;}
  puts("Migrated; original plaintext legacy file has NOT been deleted.");loaded=has_password=1;
 }
 for(;;){
  puts("\n1. Split secret (save encrypted)\n2. Recover manually\n3. Recover from stored holders\n4. Demo\n5. Delete encrypted state\n6. Export one plaintext share\n0. Exit");
  if(!line(buf,sizeof buf,"Choose: "))break;
  if(!strcmp(buf,"0"))break;
  if(!strcmp(buf,"1")){
   if(!line(buf,sizeof buf,"Secret (0-50020): "))break;
   int secret;if(!integer(buf,0,50020,&secret)){puts("Invalid secret");continue;}
   shmir_shares next;if(shmir_split(secret,&next)){puts("Random generator failed");continue;}
   if(!has_password){puts("Set a password for encrypted state.");if(!new_password(pwd,sizeof pwd))continue;}
   shmir_status s=shmir_save(&next,pwd,state);
   if(s){printf("Save failed: %s; old data unchanged\n",shmir_error(s));if(!has_password)wipe(pwd,sizeof pwd);continue;}
   shares=next;has_password=loaded=1;show(&shares);
  }else if(!strcmp(buf,"2")){if(!manual_recover())break;
  }else if(!strcmp(buf,"3")){if(!loaded)puts("No shares loaded.");else if(!select_holders(&shares))break;
  }else if(!strcmp(buf,"4")){demo();
  }else if(!strcmp(buf,"5")){
   if(!line(buf,sizeof buf,"Type YES to delete encrypted state: "))break;
   if(!strcmp(buf,"YES")){shmir_status s=shmir_delete(state);
    if(s==SHMIR_OK||s==SHMIR_NOT_FOUND){loaded=has_password=0;wipe(pwd,sizeof pwd);puts("Encrypted state deleted (not secure erasure).");}
    else printf("Delete failed: %s\n",shmir_error(s));}
  }else if(!strcmp(buf,"6")){
   if(!loaded){puts("No shares loaded");continue;}
   if(!line(buf,sizeof buf,"Holder (1-5): "))break;
   int holder;if(!integer(buf,1,5,&holder)){puts("Invalid holder");continue;}
   if(!line(buf,sizeof buf,"New export file path: "))break;
   char path[4096];snprintf(path,sizeof path,"%s",buf);
   if(!line(buf,sizeof buf,"Plaintext export! Type YES: "))break;
   if(!strcmp(buf,"YES")){shmir_status s=shmir_export(&shares,holder,path);printf("Export: %s\n",shmir_error(s));}
  }else puts("Choose 0-6.");
 }
 cleanup:wipe(pwd,sizeof pwd);
}
int main(int argc,char **argv){
 int no_alt=0;
 for(int i=1;i<argc;i++){
  if(!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")||!strcmp(argv[i],"help")){help();return 0;}
  if(!strcmp(argv[i],"--demo")){demo();return 0;}
  if(!strcmp(argv[i],"--setup")){return clean_setup();}
  if(!strcmp(argv[i],"--test")){
   char testpath[4096];const char *slash=strrchr(argv[0],'/');
   if(slash){size_t n=(size_t)(slash-argv[0]);
    if(n+13<sizeof testpath){memcpy(testpath,argv[0],n);testpath[n]=0;strcat(testpath,"/shmir-tests");execl(testpath,"shmir-tests",(char*)NULL);}
   }
   execlp("shmir-tests","shmir-tests",(char*)NULL);
   fputs("Test executable not found; run ctest --test-dir build\n",stderr);return 1;
  }
  if(!strcmp(argv[i],"--no-alt-screen")){no_alt=1;continue;}
  fprintf(stderr,"Unknown argument: %s\n",argv[i]);return 2;
 }
 int alt=!no_alt&&isatty(STDIN_FILENO)&&isatty(STDOUT_FILENO)&&getenv("TERM")&&strcmp(getenv("TERM"),"dumb");
 if(alt){fputs("\033[?1049h",stdout);fflush(stdout);}interactive();
 if(alt){fputs("\033[?1049l",stdout);fflush(stdout);}return 0;
}
