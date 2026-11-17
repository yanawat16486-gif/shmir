/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "shmir/shmir.h"
#include <stdio.h>
#include <stdlib.h>
shmir_status shmir_state_path(char *buf,size_t cap,int legacy){
 if(!buf||!cap)return SHMIR_INVALID;
 const char *base=getenv("XDG_STATE_HOME"); char homebase[4096];
 if(!base||!*base){const char *home=getenv("HOME");if(!home||!*home)return SHMIR_IO;
  int n=snprintf(homebase,sizeof homebase,"%s/.local/state",home);if(n<0||(size_t)n>=sizeof homebase)return SHMIR_IO;base=homebase;}
 int n=snprintf(buf,cap,"%s/shamir-secret-sharing/%s",base,legacy?"shares.json":"shares.enc");
 return n<0||(size_t)n>=cap?SHMIR_IO:SHMIR_OK;
}
