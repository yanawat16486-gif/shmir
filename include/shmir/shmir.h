/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef SHMIR_SHMIR_H
#define SHMIR_SHMIR_H
#include <stddef.h>
#include <stdint.h>
#define SHMIR_PRIME 50021
#define SHMIR_N 5
#define SHMIR_K 3

typedef struct { int x, y; } shmir_share;
typedef struct { shmir_share items[SHMIR_N]; } shmir_shares;
typedef enum {
 SHMIR_OK=0, SHMIR_INVALID=-1, SHMIR_CRYPTO=-2, SHMIR_IO=-3,
 SHMIR_AUTH=-4, SHMIR_FORMAT=-5, SHMIR_NOT_FOUND=-6, SHMIR_EXISTS=-7
} shmir_status;
/* A nonzero quadratic coefficient is required; coefficients and secret in [0,50020]. */
shmir_status shmir_create(int secret, int a1, int a2, shmir_shares *out);
shmir_status shmir_split(int secret, shmir_shares *out);
shmir_status shmir_recover(const shmir_share *in, size_t n, int *secret);
shmir_status shmir_validate(const shmir_shares *shares);
/* Path defaults to $XDG_STATE_HOME/shamir-secret-sharing/shares.enc. */
shmir_status shmir_state_path(char *buffer, size_t cap, int legacy);
shmir_status shmir_save(const shmir_shares *shares, const char *password, const char *path);
shmir_status shmir_load(shmir_shares *shares, const char *password, const char *path);
shmir_status shmir_load_legacy(shmir_shares *shares, const char *path);
shmir_status shmir_export(const shmir_shares *shares, int holder, const char *path);
shmir_status shmir_delete(const char *path);
const char *shmir_error(shmir_status status);
#endif
