/*
 * Copyright (c) 2010, aCaB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the <organization> nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _CRTMGR_H
#define _CRTMGR_H

#include <stdint.h>

struct crtmgr;

struct crtmgr *crtmgr_init(uint8_t log_level);
struct crtmgr *crtmgr_verify(struct crtmgr *c, const char *issuer, uint32_t sig_type, const uint8_t *sig, const void *digest, uint32_t digest_size, uint8_t log_level);
int crtmgr_add_key_from_blob(struct crtmgr *c, uint8_t *blob, uint32_t blob_size, uint8_t log_level);
void crtmgr_destroy(struct crtmgr *c);

void sha1sum(const void *digest, size_t len, uint8_t sha1[20]);
int decrypt_aes_128_cbc(void *cipher, void *plain, int len, const uint8_t secret[16], const uint8_t iv[16], uint8_t log_level);


#endif
