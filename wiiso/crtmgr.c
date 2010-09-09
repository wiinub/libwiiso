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

#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "wiiso.h"
#include "disc.h"
#include "crtmgr.h"
#include "common.h"
#include "secret.h"
#include "log.h"

struct crtmgr {
    RSA *public_key;
    struct crtmgr *parent;
    struct crtmgr *next; /* simple singly linked list */
    uint32_t key_type;
    char identity[0x41]; /* safe string */
};


static void crtmgr_print_details(const struct crtmgr *c, uint8_t log_level) {
    BIO *bio_out;

    if(log_level >= WIISO_LOG_DEBUG) {
	if(c->parent)
	    log_debug(log_level, "Dump of %s public key %s (certified by %s):\n", get_key_name(c->key_type), c->identity, c->parent->identity);
	else
	    log_debug(log_level, "Dump of %s public key %s (Root CA):\n", get_key_name(c->key_type), c->identity);

	if(!(bio_out = BIO_new_fp(stderr, BIO_NOCLOSE))) {
	    log_error(log_level, "cannot print key dump: unable to create bio\n");
	    return;
	}
	PEM_write_bio_RSA_PUBKEY(bio_out, c->public_key);
	BIO_free(bio_out);
    }
}


static RSA *crtmgr_new_rsa_pubkey(const uint8_t *mod, uint32_t mod_len, const uint8_t *exp, uint32_t exp_len, uint8_t log_level) {
    RSA *rsa;

    if(!(rsa = RSA_new())) {
	log_error(log_level, "crtmgr_new_rsa_pubkey: cannot allocate RSA struct: %s\n", ERR_error_string(ERR_get_error(), NULL));
	return NULL;
    }

    if(!(rsa->n = BN_bin2bn(mod, mod_len, NULL))) {
	log_error(log_level, "crtmgr_new_rsa_pubkey: cannot init modulus: %s\n", ERR_error_string(ERR_get_error(), NULL));
	RSA_free(rsa);
	return NULL;
    }

    if(!(rsa->e = BN_bin2bn(exp, exp_len, NULL))) {
	log_error(log_level, "crtmgr_new_rsa_pubkey: cannot init exponent: %s\n", ERR_error_string(ERR_get_error(), NULL));
	RSA_free(rsa);
	return NULL;
    }

    return rsa;
}


struct crtmgr *crtmgr_init(uint8_t log_level) {
    struct crtmgr *c = malloc(sizeof(*c));

    if(!c) {
	log_error(log_level, "crtmgr_init: OOM\n");
	return NULL;
    }

    if(!(c->public_key = crtmgr_new_rsa_pubkey((uint8_t *)ROOT_CA_MOD, sizeof(ROOT_CA_MOD)-1, (uint8_t *)ROOT_CA_EXP, sizeof(ROOT_CA_EXP)-1, log_level))) {
	log_error(log_level, "crtmgr_init: failed\n");
	free(c);
	return NULL;
    }

    c->parent = NULL;
    c->next = NULL;
    c->key_type = 0;

    memset(c->identity, 0, sizeof(c->identity));
    strcpy((char *)c->identity, "Root");

    log_debug(log_level, "crtmgr_init: initialized with root CA:\n");
    crtmgr_print_details(c, log_level);
    return c;
}


struct crtmgr *crtmgr_verify(struct crtmgr *c, const char *issuer, uint32_t sig_type, const uint8_t *sig, const void *digest, uint32_t digest_size, uint8_t log_level) {
    struct crtmgr *cur_c;
    uint32_t sig_len = get_sig_len(sig_type), cas_num = 0;
    char ca_chain[0x41], *cas[0x41], *last_ca;
    uint8_t digest_hash[20];

    if(!sig_len)
	return NULL;

    strcpy(ca_chain, issuer);
    memset(cas, 0, sizeof(cas));
    while ((last_ca = strrchr(ca_chain, '-'))) {
	*last_ca = '\0';
	cas[cas_num++] = last_ca + 1;
    }
    cas[cas_num++] = ca_chain;

    for(cur_c = c; cur_c; cur_c = cur_c->next) {
	struct crtmgr *parent_c;
	uint32_t i;

	if(cur_c->key_type != sig_type || strcmp(cur_c->identity, cas[0]))
	    continue;

	parent_c = cur_c;
	for(i=1; i<cas_num; i++) {
	    parent_c = parent_c->parent;
	    if(!parent_c || strcmp(parent_c->identity, cas[i]))
		break;
	}
	if(i != cas_num)
	    continue;

	break;
    }
    if(!cur_c) {
	log_warning(log_level, "warning: no matching CA to verify %s\n", issuer);
	return NULL;
    }

    /* {  */
    /* 	BN_CTX *c = BN_CTX_new(); */
    /* 	BIGNUM *s = BN_bin2bn(sig, sig_len, NULL); */
    /* 	BIGNUM *r = BN_new(); */
    /* 	char *bn; */
    /* 	BN_mod_exp(r, s, cur_c->public_key->e, cur_c->public_key->n, c); */
    /* 	bn = BN_bn2hex(r); */

    /* 	printf(">>>>%s\n", bn); */
    /* 	OPENSSL_free(bn); */

    /* 	BN_free(r); */
    /* 	BN_free(s); */
    /* 	BN_CTX_free(c); */
    /* } */

    sha1sum(digest, digest_size, digest_hash);
    if(!RSA_verify(NID_sha1, digest_hash, sizeof(digest_hash), (unsigned char *)sig, sig_len, cur_c->public_key)) {
	if(!*digest_hash) {
	    log_warning(log_level, "warning: digest is trucha signed, assuming valid\n");
	    return cur_c;
	}
	log_warning(log_level, "warning: verification failed for %s\n", issuer);
	return NULL;
    }

    return cur_c;
}


int crtmgr_add_key_from_blob(struct crtmgr *c, uint8_t *blob, uint32_t blob_size, uint8_t log_level) {
    struct crtmgr *parent_c, *new_c;
    uint32_t sig_type, sig_len, key_type, key_len, digest_len;
    uint8_t *sig, *issuer, *key, *identity, *exp;
    char safe_issuer[0x40 + 1], safe_identity[0x40 + 1];

    if(blob_size < 4) {
	log_warning(log_level, "warning: failed to add key - insufficient buffer for signature type\n");
	return 0;
    }
    sig_type = be32_to_host(blob);
    sig_type -= 0x10000;
    blob_size -= 4;

    sig_len = get_sig_len(sig_type);
    if(!sig_len) {
	log_warning(log_level, "warning: signature type %u not supported\n", sig_type);
	return 0;
    }
    
    if(blob_size < sig_len + 0x3c) {
	log_warning(log_level, "warning: failed to add key - insufficient buffer for signature\n");
	return 0;
    }
    sig = blob + 4;
    blob_size -= sig_len + 0x3c;

    if(blob_size < 0x40) {
	log_warning(log_level, "warning: failed to add key - insufficient buffer for issuer\n");
	return 0;
    }	
    issuer = sig + sig_len + 0x3c;
    memcpy(safe_issuer, issuer, 0x40);
    safe_issuer[sizeof(safe_issuer)-1] = '\0';
    blob_size -= 0x40;

    if(blob_size < 4) {
	log_warning(log_level, "warning: failed to add key - insufficient buffer for key type\n");
	return 0;
    }
    key = issuer + 0x40;
    key_type = be32_to_host(key);
    blob_size -= 4;

    if(blob_size < 0x40) {
	log_warning(log_level, "warning: failed to add key - insufficient buffer for identity\n");
	return 0;
    }
    identity = key + 4;
    memcpy(safe_identity, identity, 0x40);
    safe_identity[sizeof(safe_identity)-1] = '\0';
    blob_size -= 0x40;

    key_len = get_sig_len(key_type);
    if(!key_len) {
	log_warning(log_level, "warning: key type %u not supported\n", key_type);
	return 0;
    }

    if(blob_size < key_len + 4 + 4 + 0x34) {
	log_warning(log_level, "warning: failed to add key - insufficient buffer for key\n");
	return 0;
    }	
    
    key = identity + 0x40 + 4; // FIXME: WTF are these 4 bytes?
    exp = key + key_len;
    digest_len = exp - issuer + 4 + 0x34; // FIXME 34 fixed padding?
    blob_size -= key_len + 4 + 4 + 0x34;

    if(!(parent_c = crtmgr_verify(c, safe_issuer, sig_type, sig, issuer, digest_len, log_level))) {
	log_warning(log_level, "warning: couldn't find a valid signer for %s (issuer: %s)\n", safe_identity, safe_issuer);
    } else if(!(new_c = malloc(sizeof(*new_c)))) {
	log_error(log_level, "warning: OOM when adding key %s\n", safe_identity);
    } else if(!(new_c->public_key = crtmgr_new_rsa_pubkey(key, key_len, exp, 4, log_level))) {
	log_warning(log_level, "warning: failed to add key %s\n", safe_identity);
	free(new_c);
    } else {
	new_c->parent = parent_c;
	new_c->next = parent_c->next;
	new_c->key_type = key_type;
	memset(new_c->identity, 0, sizeof(new_c->identity));
	strcpy(new_c->identity, safe_identity);
	parent_c->next = new_c;
	log_debug(log_level, "crtmgr_add_key_from_blob: key %s added:\n", safe_identity);
	crtmgr_print_details(new_c, log_level);
    }

    return issuer - blob + digest_len;
}


void crtmgr_destroy(struct crtmgr *c) {
    struct crtmgr *cur = c, *next;
    while(cur) {
	RSA_free(cur->public_key);
	next = cur->next;
	free(cur);
	cur = next;
    }
}


void sha1sum(const void *digest, size_t len, uint8_t sha1[20]) {
    EVP_MD_CTX dctx;

    EVP_DigestInit(&dctx, EVP_sha1());
    EVP_DigestUpdate(&dctx, digest, len);
    EVP_DigestFinal(&dctx, sha1, NULL);
}


int decrypt_aes_128_cbc(void *cipher, void *plain, int len, const uint8_t secret[16], const uint8_t iv[16], uint8_t log_level) {
    EVP_CIPHER_CTX ctx;
    int todo, ret = 1;

    EVP_CIPHER_CTX_init(&ctx);
    do {
	if(!EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, secret, iv)) {
	    log_warning(log_level, "EVP_DecryptInit failed\n");
	    break;
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	todo = len;
	if(!EVP_DecryptUpdate(&ctx, plain, &todo, cipher, len)) {
	    log_warning(log_level, "EVP_DecryptUpdate failed\n");
	    break;
	}
	todo = len - todo;
	if(!EVP_DecryptFinal(&ctx, (uint8_t *)plain + len - todo, &todo)) {
	    log_warning(log_level, "EVP_DecryptFinal failed\n");
	    break;
	}
	ret = 0;
    } while(0);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return ret;
}

