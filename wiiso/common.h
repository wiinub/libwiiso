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


#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h>
#include <arpa/inet.h>

#define MIN(a,b) ( (a <= b) ? (a) : (b) )

static __inline__ uint32_t be32_to_host(const void *num) {
    const uint8_t *be32 = num;
    return ((uint32_t)be32[0]<<24) | ((uint32_t)be32[1]<<16) | ((uint32_t)be32[2]<<8) | be32[3];
}

static __inline__ uint16_t be16_to_host(const void *num) {
    const uint8_t *be32 = num;
    return  ((uint32_t)be32[0]<<8) | be32[1];
}

static __inline__ off_t fourtimes(uint32_t off_lo) {
    return (off_t)ntohl(off_lo)<<2;
}

static __inline__ const char *get_key_name(uint32_t key_type) {
    switch(key_type) {
    case 0: /* rsa 4096 */
	return "RSA-4096";

    case 1: /* rsa 2048 */
	return  "RSA-2048";

    case 2: /* EC */
	return 0;
	return "EC"; // FIXME
    }
    return "UNKNOWN(!)";
}

static __inline__ uint32_t get_sig_len(uint32_t sig_type) {
    switch(sig_type) {
    case 0: /* rsa 4096 */
	return 0x200;

    case 1: /* rsa 2048 */
	return  0x100;

    case 2: /* EC */
	return 0;
	return 0x40; // FIXME
    }
    return 0;
}

#endif
