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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stddef.h>

#include "disc.h"
#include "common.h"
#include "secret.h"
#include "log.h"

#define THIRTYTWOZEROES "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"



static char *to_hex(wiiso_t disc, const uint8_t *hex, unsigned int size) {
    unsigned int i;
    size = MIN(size, (sizeof(disc->log_buffer) -1) / 2);
    for(i=0; i<size; i++)
	sprintf(&disc->log_buffer[i*2], "%02x", *hex++);
    return disc->log_buffer;
}


int is_open(wiiso_t disc) {
    return disc->split_parts > 0 && disc->f[0] && (disc->type == DISC_ISO || disc->type == DISC_WBFS);
}


static int stat_disc_parts(wiiso_t disc) {
    unsigned int i;

    for(i=0; i<disc->split_parts; i++) {
	struct stat sb;
	if(fstat(fileno(disc->f[i]), &sb)) {
	    wiiso_close(disc);
	    log_error(disc->log_level, "stat_disc_parts: failed to stat file part %u\n", i);
	    return 1;
	}
	disc->split_part_sizes[i] = sb.st_size;
    }

    return 0;
}


static int disc_read(wiiso_t disc, off_t offset, void *dest, off_t len) {
    unsigned int i;
    uint8_t *curdst = (uint8_t *)dest;


    if(!len) {
	log_debug(disc->log_level, "disc_read: attempted null read\n");
	return 0;
    }

    for(i=0; i<disc->split_parts; i++) {
	if(offset >= disc->split_part_sizes[i])
	    offset -= disc->split_part_sizes[i];
	else
	    break;
    }
    if(i == disc->split_parts) {
	log_error(disc->log_level, "disc_read: attempted to read %s starting beyond the end of the last file\n", disc->filename);
	return 1;
    }

    fseeko(disc->f[i], offset, SEEK_SET);
    while(len) {
	off_t readsz = MIN(len, disc->split_part_sizes[i] - offset);
	if(fread(curdst, readsz, 1, disc->f[i]) != 1) {
	    log_error(disc->log_level, "disc_read: failed to read from %s\n", disc->filename);
	    return 1;
	}
	len -= readsz;
	offset += readsz;
	curdst += readsz;
	if(len && offset == disc->split_part_sizes[i]) {
	    i++;
	    if(i == disc->split_parts) {
		log_error(disc->log_level, "disc_read: attempted to read %s beyond the end of the last file\n", disc->filename);
		return 1;
	    }
	    offset = 0;
	    fseeko(disc->f[i], 0, SEEK_SET);
	}
    }
	    
    return 0;
}


int disc_iso_read_with_blanks(wiiso_t disc, off_t iso_offset, void *dest, off_t len, int blanks_ok) {
    uint8_t *curdst = (uint8_t *)dest;
    uint32_t start_sector, end_sector, skip;


    if(!len) {
	log_debug(disc->log_level, "disc_iso_read: attempted null read\n");
	return 0;
    }

    if(disc->type == DISC_ISO)
	return disc_read(disc, iso_offset, dest, len);

    start_sector = iso_offset / disc->wbfs_sector_size;
    skip = iso_offset % disc->wbfs_sector_size;
    end_sector = (iso_offset + len - 1) / disc->wbfs_sector_size;

    for(; start_sector <= end_sector; start_sector++) {
	uint32_t readsz;
	uint16_t entry;

	if(start_sector >= disc->wbfs_table_entries) {
	    log_error(disc->log_level, "disc_iso_read: attempted to read beyond the wbfs table of file %s (iso_offset: %llx, table_entry: %x, total entries: %x)\n",
		      disc->filename, (unsigned long long)iso_offset, start_sector, disc->wbfs_table_entries);
	    return 1;
	}

	entry = ntohs(disc->wbfs_table[start_sector]);
	if(!entry && !blanks_ok) {
	    log_error(disc->log_level, "disc_iso_read: attempted to read a sector which is not in the wbfs table of file %s\n", disc->filename);
	    return 1;
	}

	if(entry >= disc->wbfs_table_max) {
	    log_error(disc->log_level, "disc_iso_read: attempted to read a sector which the wbfs table maps beyond the EOF of file %s\n", disc->filename);
	    return 1;
	}

	readsz = MIN(len, disc->wbfs_sector_size - skip);
	if(!entry)
	    memset(curdst, 0, readsz);
	else if(disc_read(disc, skip + (uint32_t)entry * disc->wbfs_sector_size, curdst, readsz)) {
	    log_error(disc->log_level, "disc_iso_read: failed to read from %s\n", disc->filename);
	    return 1;
	}
	len -= readsz;
	curdst += readsz;
	skip = 0;
    }

    return 0;
}

int disc_iso_read(wiiso_t disc, off_t iso_offset, void *dest, off_t len) {
    return disc_iso_read_with_blanks(disc, iso_offset, dest, len, 0);
}

static int read_data_sector(wiiso_t disc, uint32_t partition, off_t sector_offset, int *verified) {
    struct partition_data *p = &disc->partitions[partition];
    struct sector_header *encrypted_sect_header = &disc->raw_sector.header, *plain_sect_header = &disc->plain_sector.header;
    union sector_data *encrypted_sect_data = &disc->raw_sector.data, *plain_sect_data = &disc->plain_sector.data;
    const off_t sect_num = sector_offset / 0x8000, rel_sector = sector_offset;
    uint8_t sha1[31][20], sect_sha1[20], iv[16];
    unsigned int j, bad_sector = 0;

    if(sector_offset % 0x8000) {
	log_error(disc->log_level, "read_data_sector: unaligned offset %llx\n", (unsigned long long)sector_offset);
	return 1;
    }

    sector_offset += p->data_offset;
    if(sector_offset == disc->last_plain_sector) {
	if(verified) *verified = disc->last_verified;
	return 0;
    }
    if(rel_sector > p->data_size || rel_sector + sizeof(disc->raw_sector) > p->data_size) {
    	log_error(disc->log_level, "read_data_sector: attempted to read data sector @%llx (abs: %llx) which is outside partition %u data area\n", (unsigned long long)rel_sector, (unsigned long long)sector_offset, partition);
    	return 1;
    }

    /* Read sector (header and data) */
    if(disc_iso_read(disc, sector_offset, &disc->raw_sector, sizeof(disc->raw_sector))) {
	log_error(disc->log_level, "read_data_sector: failed to read data sector @%llx (abs: %llx) on partition %u\n", (unsigned long long)rel_sector, (unsigned long long)sector_offset, partition);
    	return 1;
    }

    /* Check for null or scrubbed sector - ideally we should never land here if we stick to the actual content */
    sha1sum(&disc->raw_sector.data, sizeof(disc->raw_sector.data), sect_sha1);
    if(!memcmp(sect_sha1, "\xd9\x55\xe4\x4f\xf6\x3f\xda\x3f\x9b\x18\xf1\x9a\xa7\x2c\xbb\xa4\x3a\x5d\x8e\x44", sizeof(sect_sha1)) ||
       !memcmp(sect_sha1, "\xee\x61\xa3\xeb\x77\xc2\x7d\xb5\x05\x84\x6a\xba\xf3\xac\x8a\x4f\xc3\xf8\x79\xda", sizeof(sect_sha1))) {
    	log_warning(disc->log_level, "read_data_sector: skipping scrubbed/NULL sector @%llx (abs: %llx) of partition %u\n", (unsigned long long)rel_sector, (unsigned long long)sector_offset, partition);
    	memmove(&disc->plain_sector, &disc->raw_sector, sizeof(disc->raw_sector));
	disc->last_plain_sector = sector_offset;
	disc->last_verified = 0;
	if(verified) *verified = 0;
	return 0;
    }

    /* Decrypt encrypted sector header to plain sector header */
    memset(iv, 0, sizeof(iv));
    if(decrypt_aes_128_cbc(encrypted_sect_header, plain_sect_header, sizeof(*encrypted_sect_header), p->plain_title_key, iv, disc->log_level)) {
    	log_error(disc->log_level, "read_data_sector: failed to decrypt sector header @%llx (abs: %llx) of partition %u\n", (unsigned long long)rel_sector, (unsigned long long)sector_offset, partition);
	bad_sector = 1;
    }

    /* Check that it really looks like a header */
    if(!bad_sector && (
       memcmp(THIRTYTWOZEROES, plain_sect_header->pad0, sizeof(plain_sect_header->pad0)) ||
       memcmp(THIRTYTWOZEROES, plain_sect_header->pad1, sizeof(plain_sect_header->pad1)) ||
       memcmp(THIRTYTWOZEROES, plain_sect_header->pad2, sizeof(plain_sect_header->pad2)))
       ) {
	log_warning(disc->log_level, "read_data_sector: possibly corrupted sector header @%llx (abs: %llx) of partition %u\n", (unsigned long long)rel_sector, (unsigned long long)sector_offset, partition);
    }

    /* for(j=0; j<31; j++) */
    /* 	log_debug(disc->log_level, "read_data_sector: h0 [%02x]: %s\n", j, to_hex(disc, plain_sect_header->h0[j], sizeof(plain_sect_header->h0[0]))); */

    /* for(j=0; j<8; j++) */
    /* 	log_debug(disc->log_level, "read_data_sector: h1 [%02x]: %s\n", j, to_hex(disc, plain_sect_header->h1[j], sizeof(plain_sect_header->h1[0]))); */

    /* for(j=0; j<8; j++) */
    /* 	log_debug(disc->log_level, "read_data_sector: h2 [%02x]: %s\n", j, to_hex(disc, plain_sect_header->h2[j], sizeof(plain_sect_header->h2[0]))); */

    /* Decrypt sector data (key=title_key, iv=bottom of h2) */
    memcpy(iv, &encrypted_sect_header->h2[7][20-16], 16);
    if(decrypt_aes_128_cbc(encrypted_sect_data, plain_sect_data, sizeof(*encrypted_sect_data), p->plain_title_key, iv, disc->log_level)) {
    	log_warning(disc->log_level, "read_data_sector: failed to decrypt sector data @ offset %llx\n", (unsigned long long)sector_offset);
    	bad_sector = 1;
    }

    if(!bad_sector && p->can_be_verified) {
	do {
	    /* Hash each of the 31 data chunks and match them against the 31 h0's */
	    for(j=0; j<31; j++) {
		sha1sum(plain_sect_data->chunk[j], sizeof(plain_sect_data->chunk[0]), sha1[j]);
		if(memcmp(plain_sect_header->h0[j], sha1[j], sizeof(sha1[0]))) {
		    log_warning(disc->log_level, "read_data_sector: h0 mismatch @offset %llx on chunk %02x - computed: %s", (unsigned long long)sector_offset, j, to_hex(disc, sha1[j], sizeof(sha1[0])));
		    log_warning(disc->log_level, " - reference: %s\n", to_hex(disc, plain_sect_header->h0[j], sizeof(plain_sect_header->h0[0])));
		    bad_sector = 1;
		    break;
		}     
	    }
	    if(j!=31)
		break;

	    /* Hash the above 31 hashes and compare it against the proper entry in h1 */
	    sha1sum(sha1, sizeof(sha1), sect_sha1);
	    if(memcmp(sect_sha1, plain_sect_header->h1[sect_num % 64 % 8], 20)) {
		log_warning(disc->log_level, "read_data_sector: h1 mismatch @offset %llx - computed: %s", (unsigned long long)sector_offset, to_hex(disc, sect_sha1, sizeof(sect_sha1)));
		log_warning(disc->log_level, " - reference: %s\n", to_hex(disc, plain_sect_header->h1[sect_num % 64 % 8], sizeof(plain_sect_header->h1[0])));
		bad_sector = 1;
		break;
	    }

	    /* Hash the whole h1 and compare it against the proper entry in h2 */
	    sha1sum(plain_sect_header->h1, sizeof(plain_sect_header->h1), sect_sha1);
	    if(memcmp(sect_sha1, plain_sect_header->h2[sect_num % 64 / 8], 20)) {
		log_warning(disc->log_level, "read_data_sector: h2 mismatch @offset %llx - computed: %s", (unsigned long long)sector_offset, to_hex(disc, sect_sha1, sizeof(sect_sha1)));
		log_warning(disc->log_level, " - reference: %s\n", to_hex(disc, plain_sect_header->h2[sect_num % 64 / 8], sizeof(plain_sect_header->h2[0])));
		bad_sector = 1;
		break;
	    }

	    /* Hash the whole h2 and compare it to the proper entry in h3 */
	    sha1sum(plain_sect_header->h2, sizeof(plain_sect_header->h2), sect_sha1);
	    if(memcmp(sect_sha1, p->h3.sha1[sect_num / 64], 20)) {
		log_warning(disc->log_level, "read_data_sector: h3 mismatch @offset %llx - computed: %s", (unsigned long long)sector_offset, to_hex(disc, sect_sha1, sizeof(sect_sha1)));
		log_warning(disc->log_level, " - reference: %s\n", to_hex(disc, p->h3.sha1[sect_num / 64], sizeof(p->h3.sha1[0])));
		bad_sector = 1;
		break;
	    }
	} while(0);
    }
    
    disc->last_plain_sector = sector_offset;
    disc->last_verified = !bad_sector;
    if(verified) *verified = disc->last_verified;
    return 0;
}


int read_data(wiiso_t disc, uint32_t partition, off_t data_offset, off_t data_len, void *dest, int *verified) {
    uint8_t *curdata = (uint8_t *)dest;
    off_t first_sector, last_sector, cur_sector;
    int sector_verified;
    uint32_t head;

    if(verified)
	*verified = 1;
    if(!data_len)
	return 0;

    first_sector = data_offset / 0x7c00;
    last_sector = (data_offset + data_len - 1) / 0x7c00;
    head = data_offset % 0x7c00;

    for(cur_sector = first_sector; cur_sector <= last_sector; cur_sector++) {
	uint32_t avail;

	if(read_data_sector(disc, partition, cur_sector * 0x8000, &sector_verified))
	    return 1;
	if(verified)
	    *verified &= sector_verified;

	avail = MIN(sizeof(disc->plain_sector.data.raw) - head, data_len);
	if(curdata) {
	    memcpy(curdata, &disc->plain_sector.data.raw[head], avail);
	    curdata += avail;
	}
	data_len -= avail;
	head = 0;
    }
    return 0;
}



static int validate_iso_header(wiiso_t disc) {
    char *iso_name;
    unsigned int i;
    
    if(disc->iso_header.magic != htonl(0x5d1c9ea3)) {
	log_error(disc->log_level, "validate_iso_header: %s is not a wii iso disk\n", disc->filename);
	return 1;
    }

    disc->iso_header.id_term = '\0';
    log_debug(disc->log_level, "validate_iso_header: iso ID: >%s<\n", disc->iso_header.id);

    disc->iso_header.name_term = '\0';
    iso_name = &disc->iso_header.name[strspn(disc->iso_header.name, " ")];

    i = strlen(iso_name);
    do {
	i--;
	if(iso_name[i] == ' ')
	    iso_name[i] = '\0';
	else
	    break;
    } while(i);
			
    log_debug(disc->log_level, "validate_iso_header: iso title: >%s<\n", iso_name);
    return 0;
}


const char *part_type(uint32_t type) {
    switch(type) {
    case 0:
	return "Data";
    case 1:
	return "Update";
    case 2:
	return "Channel";
    }
    return "Unknown";
}


static void parse_cert_chain(wiiso_t disc, uint32_t partition) {
    struct partition_data *p = &disc->partitions[partition];
    uint32_t parsed_len = 0, num_certs = 0;
    uint8_t *crt = NULL;

    do {
	if(!p->crt_size) {
	    log_warning(disc->log_level, "parse_cert_chain: no certificate chain found in partition %u\n", partition);
	    break;
	}

	if(!(crt = malloc(p->crt_size))) {
	    log_warning(disc->log_level, "parse_cert_chain: out of memory when allocating the certificate chain (%u bytes) for partition %u\n", p->crt_size, partition);
	    break;
	}

	if(disc_iso_read(disc, p->crt_offset, crt, p->crt_size)) {
	    log_warning(disc->log_level, "parse_cert_chain: failed to read the certificate chain of partition %u\n", partition);
	    break;
	}

	p->cert_chain = crtmgr_init(disc->log_level);
	if(!p->cert_chain) {
	    log_warning(disc->log_level, "parse_cert_chain: failed to init the certificate manager for partition %u\n", partition);
	    break;
	}

	while(parsed_len < p->crt_size) {
	    uint32_t cert_len;

	    cert_len = crtmgr_add_key_from_blob(p->cert_chain, crt + parsed_len, p->crt_size - parsed_len, disc->log_level);
	    if(!cert_len)
		break;
	    parsed_len += cert_len;
	    num_certs++;
	}
	if(!num_certs) {
	    crtmgr_destroy(p->cert_chain);
	    p->cert_chain = NULL;
	    log_warning(disc->log_level, "parse_cert_chain: no usable certificate found in partition %u", partition);
	}
    } while(0);

    if(crt)
	free(crt);

    if(!p->cert_chain) {
	p->can_be_verified = 0;
	log_warning(disc->log_level, "parse_cert_chain: verification of partition data disabled for partition %u\n", partition);
    } else
	log_debug(disc->log_level, "parse_cert_chain: certificate chain successfully imported for partition %u\n", partition);
}


static void parse_tmd(wiiso_t disc, uint32_t partition) {
    struct partition_data *p = &disc->partitions[partition];
    int h4_verified = 0;
    uint8_t *tmd = NULL;


    if(!p->can_be_verified) {
	log_warning(disc->log_level, "parse_tmd: skipping TMD parsing because h4 cannot be verified\n");
	return;
    }

    do { /* Parse tmd */
	uint16_t contents;
	struct CONTENT {
	    uint8_t content_id[4];
	    uint8_t index[2];
	    uint8_t type[2];
	    uint8_t size[8];
	    uint8_t sha1[20];
	} *tmd_content;
	int h4_checked = 0;

	if(p->tmd_size < 0x1e4) {
	    log_warning(disc->log_level, "parse_tmd: will not parse too small TMD\n");
	    break;
	}
	if(!(tmd = malloc(p->tmd_size))) {
	    log_warning(disc->log_level, "parse_tmd: out of memory memory when allocating TMD structures (%u bytes) for partition %u\n", p->tmd_size, partition);
	    break;
	}

	if(disc_iso_read(disc, p->tmd_offset, tmd, p->tmd_size)) {
	    log_warning(disc->log_level, "parse_tmd: failed to read the TMD of partition %u\n", partition);
	    break;
	}

	memcpy(disc->safe_issuer, tmd + 0x0140, sizeof(disc->safe_issuer));
	disc->safe_issuer[sizeof(disc->safe_issuer)-1] = '\0';
	if(be32_to_host(tmd) != 0x10001) {
	    log_warning(disc->log_level, "parse_tmd: TMD signed with unexpected %s key, skipping sign check\n", get_key_name(be32_to_host(tmd) - 0x10000));
	    break;
	}

	if(!crtmgr_verify(p->cert_chain, disc->safe_issuer, 1, &tmd[4], &tmd[0x140], p->tmd_size - 0x140, disc->log_level)) {
	    log_warning(disc->log_level, "parse_tmd: TMD verification failed\n");
	    break;
	}

	contents = be16_to_host(&tmd[0x1de]);
	if(p->tmd_size < 0x1e4 + contents * sizeof(*tmd_content)) {
	    log_warning(disc->log_level, "parse_tmd: will not parse overflowing TMD content\n");
	    break;
	}

	tmd_content = (struct CONTENT *) (tmd + 0x1e4);
	while(contents--) {
	    log_debug(disc->log_level, "parse_tmd: TMD content: id %x, index %x, type %x, size %x%04x, hash: %s\n", 
			be32_to_host(tmd_content->content_id),
			be16_to_host(tmd_content->index),
			be16_to_host(tmd_content->type),
			be32_to_host(tmd_content->size),
			be32_to_host(&tmd_content->size[4]),
			to_hex(disc, tmd_content->sha1, 20));
	    /* FIXME: apparently always only one entry. Type is 4001 for update and 3 for data?? */
	    if(h4_checked)
		log_warning(disc->log_level, "parse_tmd: multiple h4 found\n");
	    h4_checked = 1;
	    if(memcmp(p->h4, tmd_content->sha1, sizeof(p->h4))) {
		log_warning(disc->log_level, "parse_tmd: h4 mismatch: computed: %s", to_hex(disc, p->h4, sizeof(p->h4)));
		log_warning(disc->log_level, " reference: %s\n", to_hex(disc, tmd_content->sha1, sizeof(tmd_content->sha1)));
	    } else
		h4_verified = 1;
	}
    } while(0);
    if(tmd)
	free(tmd);

    p->can_be_verified = h4_verified;

    if(!h4_verified)
	log_warning(disc->log_level, "parse_tmd: verification of partition data disabled for partition %u\n", partition);
    else
	log_debug(disc->log_level, "parse_tmd: h4 of partition %u successfuly verified via TMD\n", partition);
}


int get_file_by_id(wiiso_t disc, uint32_t partition, uint32_t id, char **file_name, off_t *file_offset, uint32_t *file_len, uint32_t *file_parent) {
    struct partition_data *p = &disc->partitions[partition];
    off_t foffset;
    uint32_t parent, fsize;
    uint8_t *entry;
    char *name;

    if(id >= p->fst_files) {
	log_warning(disc->log_level, "get_file_by_id: entry %u > fst_files (%u) in partition %u\n", id, p->fst_files, partition);
	return 1;
    }

    name = (char *)(p->fst + p->fst_files * 12);
    entry = p->fst + 12 * id;
    if(entry + 12 > (uint8_t *)name) {
	log_warning(disc->log_level, "get_file_by_id: entry %u > names in partition %u\n", id, partition);
	return 1;
    }

    if(id) {
	name += be32_to_host(entry) & 0xffffff;
	if((uint8_t *)name >= p->fst + p->fst_size || !memchr(name, 0, p->fst_size - ((uint8_t *)name - p->fst))) {
	    log_warning(disc->log_level, "get_file_by_id: entry %u has name > fst_end in partition %u\n", id, partition);
	    return 1;
	}
    } else
	name = "";

    if(*entry) { /* Directory */
	parent = be32_to_host(entry + 4);
	if(parent >= p->fst_files) {
	    log_warning(disc->log_level, "get_file_by_id: entry '%s' (%u) has parent %u > fst_files (%u) in partition %u\n", name, id, parent, p->fst_files, partition);
	    return 1;
	}
	foffset = 0;
	fsize = 0;
    } else { /* File */
	foffset = (off_t)be32_to_host(entry + 4) * 4;
	fsize = be32_to_host(entry + 8);
	if(foffset >= p->data_size || foffset + fsize > p->data_size) {
	    log_warning(disc->log_level, "get_file_by_id: entry '%s' has offset %llx outside data in partition %u\n", name, (unsigned long long)foffset, partition);
	    return 1;
	}
	parent = id;
	do {
	    entry -= 12;
	    parent--;
	} while(parent && (!*entry || be32_to_host(entry + 8) <= id));
    }

    if(file_name) *file_name = name;
    if(file_offset) *file_offset = foffset;
    if(file_len) *file_len = fsize;
    if(file_parent) *file_parent = parent;
    return 0;
}


static int parse_fst(wiiso_t disc, uint32_t partition) {
    struct partition_data *p = &disc->partitions[partition];
    uint32_t i;


    if(p->fst_size < 12) {
	if(p->fst_size)
	    log_warning(disc->log_level, "parse_fst: unable to parse FST\n");
	return 0;
    }

    p->fst = malloc(p->fst_size);
    if(!p->fst) {
	log_error(disc->log_level, "parse_fst: out of memory memory when allocating FST space (%llu bytes) for partition %u\n", (unsigned long long)p->fst_size, partition);
	return 1;
    }
    if(read_data(disc, partition, p->fst_offset, p->fst_size, p->fst, NULL)) {
	log_error(disc->log_level, "parse_fst: failed to read FST of partition %u\n", partition);
	free(p->fst);
	p->fst = NULL;
	return 1;
    }

    if(memcmp(p->fst, "\x01\x00\x00\x00\x00\x00\x00\x00", 8)) {
	log_error(disc->log_level, "parse_fst: bad FST root in partition %u\n", partition);
	free(p->fst);
	p->fst = NULL;
	return 1;
    }

    p->fst_files = be32_to_host(p->fst + 8);

    for(i=0; i<p->fst_files; i++) {
	if(get_file_by_id(disc, partition, i, NULL, NULL, NULL, NULL)) {
	    log_error(disc->log_level, "parse_fst: invalid FST entry %u in partition %u\n", i, partition);
	    free(p->fst);
	    p->fst = NULL;
	    p->fst_files = 0;
	    return 1;
	}
    }

    return 0;
}


static int parse_partition_data(wiiso_t disc, uint32_t partition) {
    struct partition_data *p = &disc->partitions[partition];
    struct iso_header *data_header = &p->partition_header;
    char *part_name;
    unsigned int j;

    if(read_data_sector(disc, partition, 0, NULL)) {
	log_error(disc->log_level, "parse_partition_data: failed to read partition data\n");
	return 1;
    }

    memcpy(data_header, &disc->plain_sector.data.raw, sizeof(*data_header));

    if(data_header->magic != htonl(0x5d1c9ea3)) {
	log_error(disc->log_level, "parse_partition_data: not a wii partition\n");
	return 1;
    }

    data_header->id_term = '\0';
    data_header->name_term = '\0';
    part_name = &data_header->name[strspn(data_header->name, " ")];
    j = strlen(part_name);
    do {
	j--;
	if(part_name[j] == ' ')
	    part_name[j] = '\0';
	else
	    break;
    } while(j);

    p->fst_offset = (off_t)be32_to_host(&disc->plain_sector.data.raw[0x0424]) << 2;
    p->fst_size   = (off_t)be32_to_host(&disc->plain_sector.data.raw[0x0428]) << 2;
    p->dol_offset = (off_t)be32_to_host(&disc->plain_sector.data.raw[0x0420]) << 2;
    p->dol_size   =  p->fst_offset - p->dol_offset; /* FIXME check wraps, parse dol sections */
    p->apl_offset = 0x2460;
    p->apl_size1  = (off_t)be32_to_host(&disc->plain_sector.data.raw[0x2454]);
    p->apl_size2  = (off_t)be32_to_host(&disc->plain_sector.data.raw[0x2458]);

    log_debug(disc->log_level, "parse_partition_data: Info for partition %u\n\tID: >%s<\n\ttitle: >%s<\n\tdol: %llx -> %llx (%llx)\n\tfst: %llx -> %llx (%llx)\n\tapl1: %llx -> %llx (%llx)\n\tapl2: %llx -> %llx (%llx)\n",
	      partition,
	      data_header->id, part_name,
	      (unsigned long long)p->dol_offset, (unsigned long long)(p->dol_offset + p->dol_size), (unsigned long long)p->dol_size,
	      (unsigned long long)p->fst_offset, (unsigned long long)(p->fst_offset + p->fst_size), (unsigned long long)p->fst_size,
	      (unsigned long long)p->apl_offset, (unsigned long long)(p->apl_offset + p->apl_size1), (unsigned long long)p->apl_size1,
	      (unsigned long long)(p->apl_offset + p->apl_size1), (unsigned long long)(p->apl_offset + p->apl_size1 + p->apl_size2), (unsigned long long)p->apl_size2);

    return parse_fst(disc, partition);
}


static int parse_partition(wiiso_t disc, uint32_t partition) {
    struct partition_data *p = &disc->partitions[partition];
    struct _part_header part_header;
    uint8_t iv[16];


    /* Read partition metadata */
    if(disc_iso_read(disc, p->offset_to_partition, &part_header, sizeof(part_header))) {
	log_error(disc->log_level, "parse_partition: failed to read partition header of partition %d\n", partition);
	return 1;
    }

    p->tmd_size = ntohl(part_header.tmd_size);
    p->crt_size = ntohl(part_header.crt_size);
    p->data_size = fourtimes(part_header.data_size);

    p->tmd_offset = p->offset_to_partition + fourtimes(part_header.tmd_offset);
    p->crt_offset = p->offset_to_partition + fourtimes(part_header.crt_offset);
    p->h3_offset  = p->offset_to_partition + fourtimes(part_header.h3_offset);
    p->data_offset = p->offset_to_partition + fourtimes(part_header.data_offset);

    log_debug(disc->log_level, "parse_partition: partition info:\n\tTMD (%x bytes) @ offset %llx\n\tCertificate chain (%x bytes) @ offset %llx\n\tPartition data (%llx bytes) @ offset %llx\n\th3 @ offset %llx\n",
	      p->tmd_size, (unsigned long long)p->tmd_offset, p->crt_size, (unsigned long long)p->crt_offset, (unsigned long long)p->data_size, (unsigned long long)p->data_offset, (unsigned long long)p->h3_offset);


    /* Import cert chain */
    parse_cert_chain(disc, partition);


    /* Signcheck ticket */
    if(p->can_be_verified) {
	uint32_t sig_type = be32_to_host(part_header.ticket.sig_type) - 0x10000;

	if(sig_type == 1) {
	    memcpy(disc->safe_issuer, part_header.ticket.issuer, sizeof(part_header.ticket.issuer));
	    disc->safe_issuer[sizeof(disc->safe_issuer)-1] = '\0';
	    if(crtmgr_verify(p->cert_chain, disc->safe_issuer, 1, part_header.ticket.signature, part_header.ticket.issuer, sizeof(part_header.ticket) - offsetof(struct TICKET, issuer), disc->log_level))
		log_debug(disc->log_level, "parse_partition: ticket correctly verified for partition %u\n", partition);
	    else
		log_warning(disc->log_level, "parse_partition: ticket verification failed for partition %u\n", partition);
	} else
	    log_warning(disc->log_level, "parse_partition: ticket signed with unexpected %s key, skipping sign check for partition %u\n", get_key_name(sig_type), partition);
    } else
	log_warning(disc->log_level, "parse_partition: skipping ticket verification for partition %u\n", partition);


    /* Decrypt title key */
    memcpy(iv, part_header.ticket.title_id, sizeof(part_header.ticket.title_id));
    memset(iv + 8, 0, 8);
    if(part_header.ticket.common_key_id > 1)
	log_warning(disc->log_level, "parse_partition: unable to determine which key to use, assuming common\n");
    if(decrypt_aes_128_cbc(part_header.ticket.encrypted_key, p->plain_title_key, sizeof(part_header.ticket.encrypted_key), part_header.ticket.common_key_id != 1 ? common_key : korean_key, iv, disc->log_level)) {
	log_error(disc->log_level, "parse_partition: failed to decrypt title key for partition %u\n", partition);
	return 1;
    }
    log_debug(disc->log_level, "parse_partition: decrypted title key: %s", to_hex(disc, p->plain_title_key, sizeof(p->plain_title_key)));
    log_debug(disc->log_level, " (encrypted: %s)\n", to_hex(disc, part_header.ticket.encrypted_key, sizeof(part_header.ticket.encrypted_key)));


    /* Read h3 */
    if(p->can_be_verified) {
	p->can_be_verified = !disc_iso_read(disc, p->h3_offset, &p->h3, sizeof(p->h3));
	if(!p->can_be_verified)
	    log_warning(disc->log_level, "parse_partition: failed to read h3 of partition %u; data verification disabled\n", partition);
    } else {
	log_warning(disc->log_level, "parse_partition: skipping h3 as it cannot be verified\n");
    }


    /* Compute h4 */
    sha1sum(&p->h3, sizeof(p->h3), p->h4);
    log_debug(disc->log_level, "parse_partition: h4: %s\n", to_hex(disc, p->h4, sizeof(p->h4)));


    /* Check h4 via TMD */
    parse_tmd(disc, partition);


    /* Read partition metadata */
    return parse_partition_data(disc, partition);
}


static int parse_disc(wiiso_t disc) {
    struct _uint_pair uint_pair;
    uint32_t p;


    if(disc_iso_read(disc, 0x40000, &uint_pair, sizeof(uint_pair))) {
	log_error(disc->log_level, "parse_disc: failed to read partition data on file %s\n", disc->filename);
	return 1;
    }

    disc->num_partitions = ntohl(uint_pair.uint0);
    if(disc->num_partitions < 1 || disc->num_partitions > 64) {
	log_error(disc->log_level, "parse_disc: invalid partition count (%u) on file %s\n", disc->num_partitions, disc->filename);
	return 1;
    }

    if(!(disc->partitions = malloc(disc->num_partitions * sizeof(*disc->partitions)))) {
	log_error(disc->log_level, "parse_disc: out of memory when allocating partition data structures (%lu bytes) for file %s\n", disc->num_partitions * sizeof(*disc->partitions), disc->filename);
	return 1;
    }

    disc->off_to_part_tbl = fourtimes(uint_pair.uint1);
    log_debug(disc->log_level, "parse_disc: found %u partitions @ offset %llx\n", disc->num_partitions, (unsigned long long)disc->off_to_part_tbl);

    for(p=0; p<disc->num_partitions; p++) {
	if(disc_iso_read(disc, disc->off_to_part_tbl + 8 * p, &uint_pair, sizeof(uint_pair))) {
	    log_error(disc->log_level, "parse_disc: failed to read partition table (entry #%u)\n", p);
	    return 1;
	}
	disc->partitions[p].offset_to_partition = fourtimes(uint_pair.uint0);
	disc->partitions[p].partition_type = ntohl(uint_pair.uint1);
	disc->partitions[p].cert_chain = NULL;
	disc->partitions[p].can_be_verified = 1;
	disc->partitions[p].fst = NULL;
	disc->partitions[p].fst_files = 0;
	log_debug(disc->log_level, "parse_disc: partition %u (%s) @ offset %llx\n", p, part_type(disc->partitions[p].partition_type), (unsigned long long)disc->partitions[p].offset_to_partition);

	if(parse_partition(disc, p))
	    return 1;
    }

    return 0;
}


int read_iso_header(wiiso_t disc) {
    if(!disc->f[0]) {
	log_error(disc->log_level, "read_iso_header: bad argument\n");
	return 1;
    }

    fseeko(disc->f[0], 0, SEEK_SET);
    if(fread(&disc->iso_header, sizeof(disc->iso_header), 1, disc->f[0]) != 1) {
	log_error(disc->log_level, "read_iso_header: can't read iso header from %s\n", disc->filename);
	return 1;
    }

    if(validate_iso_header(disc))
	return 1;

    disc->type = DISC_ISO;
    disc->split_parts = 1;
    if(stat_disc_parts(disc))
	return 1;

    return parse_disc(disc);
}


int read_wbfs_header(wiiso_t disc) {
    uint8_t buf[sizeof(disc->filename)];
    uint32_t hd_sec_size, ndisks;
    off_t total_size, table_items;
    uint32_t table_size;
    int i, namelen;

    if(!disc->f[0]) {
	log_error(disc->log_level, "read_wbfs_header: bad argument\n");
	return 1;
    }

    fseeko(disc->f[0], 0, SEEK_SET);
    if(fread(buf, 16, 1, disc->f[0]) != 1) {
	log_error(disc->log_level, "read_wbfs_header: can't read wbfs header from %s\n", disc->filename);
	return 1;
    }
    
    if(memcmp(buf, "WBFS", 4)) {
	log_error(disc->log_level, "read_wbfs_header: %s is not a wbfs disk\n", disc->filename);
	return 1;
    }

    if(buf[8] >= 31 || buf[9] >= 31) {
	log_error(disc->log_level, "read_wbfs_header: bad wbfs header in file %s\n", disc->filename);
	return 1;
    }

    total_size = be32_to_host(buf + 4);
    hd_sec_size = 1<<buf[8];
    disc->wbfs_sector_size = 1<<buf[9];

    if(!hd_sec_size || !disc->wbfs_sector_size) {
	log_error(disc->log_level, "read_wbfs_header: wbfs header with null sector size in file %s\n", disc->filename);
	return 1;
    }

    total_size *= hd_sec_size;
    ndisks = be32_to_host(buf + 12);
    if(ndisks != 0x01000000) {
	log_error(disc->log_level, "read_wbfs_header: unsupported multiple discs found in file %s\n", disc->filename);
	return 1;
    }

    table_items = total_size / disc->wbfs_sector_size;
    if(table_items > 0xffff) {
	log_error(disc->log_level, "read_wbfs_header: bad header in file %s\n", disc->filename);
	return 1;
    }
    disc->wbfs_table_entries = (disc->wbfs_sector_size - 0x300) / sizeof(uint16_t);
    disc->wbfs_table_max = table_items;

    i = 1;
    namelen = strlen(disc->filename);
    if(namelen > 5 && !strcasecmp(&disc->filename[namelen-5], ".wbfs")) {
	memcpy(buf, disc->filename, namelen + 1);
	for(i=1; i<MAX_SPLIT_PARTS; i++) {
	    buf[namelen-1] = '0' + i;
	    if(!(disc->f[i] = fopen((char *)buf, "rb")))
		break;
	    log_debug(disc->log_level, "read_wbfs_header: found next part %s\n", buf);
	}
	log_debug(disc->log_level, "read_wbfs_header: file %s has %d parts\n", disc->filename, i);
    }
    disc->split_parts = i;
    disc->type = DISC_WBFS;
    if(stat_disc_parts(disc))
	return 1;

    table_size = disc->wbfs_table_entries * sizeof(uint16_t);
    disc->wbfs_table = malloc(table_size);
    if(!disc->wbfs_table) {
	log_error(disc->log_level, "read_wbfs_header: out of memory when allocating sector table for file %s\n", disc->filename);
	return 1;
    }

    if(disc_read(disc, 0x300, disc->wbfs_table, table_size)) {
	log_error(disc->log_level, "read_wbfs_header: failed to read wbfs table from file %s\n", disc->filename);
	return 1;
    }

    if(disc_iso_read(disc, 0, &disc->iso_header, sizeof(disc->iso_header))) {
	log_error(disc->log_level, "read_wbfs_header: failed to read iso header\n");
	return 1;
    }

    if(validate_iso_header(disc))
	return 1;

    log_debug(disc->log_level, "read_wbfs_header: WBFS disc info:\n\tWBFS sector size: %x\n\tDevice sector size: %x\n\tTotal available size: %llx\n\tWBFS table entries: %x\n",
	      disc->wbfs_sector_size, hd_sec_size, (unsigned long long)total_size, disc->wbfs_table_entries);

    return parse_disc(disc);
}


int verify_partition(wiiso_t disc, uint32_t partition, int verify_all_data) {
    struct partition_data *p = &disc->partitions[partition];
    int verified, ok = 1;
    uint32_t i;

    if(!p->can_be_verified)
	return 1;

    if(!p->data_size)
	return 0;

    if(verify_all_data) {
	off_t off;

	for(off = 0; off < p->data_size; off+=0x8000) {
	    if(read_data_sector(disc, partition, off, &verified))
		return 1;
	    ok &= verified;
	}
	return !ok;
    }

    if(read_data(disc, partition, p->dol_offset, p->dol_size, NULL, &verified))
	return 1;
    if(!verified)
	log_warning(disc->log_level, "verify_partition: dol verification failed\n");
    ok &= verified;

    if(read_data(disc, partition, p->apl_offset, p->apl_size1 + p->apl_size2, NULL, &verified))
	return 1;
    if(!verified)
	log_warning(disc->log_level, "verify_partition: apl verification failed\n");
    ok &= verified;

    for(i=0; i<p->fst_files; i++) {
	off_t foffset;
	uint32_t fsize;
	char *name;

	if(get_file_by_id(disc, partition, i, &name, &foffset, &fsize, NULL)) {
	    log_error(disc->log_level, "verify_partition: bad file %u\n", i);
	    return 1;
	}
	if(!foffset)
	    continue;
	if(read_data(disc, partition, foffset, fsize, NULL, &verified))
	    return 1;
	if(!verified)
	    log_warning(disc->log_level, "verify_partition: file %s verification failed\n", name);
	ok &= verified;
    }

    return !ok;
}


int mark_used(struct wbfs_table **t, off_t start_offset, off_t len, uint8_t log_level) {
    struct wbfs_table *table = *t;
    off_t first_sector, last_sector;
    uint32_t sector_size, num_entries;

    if(!table) {
	sector_size = 0x80000; /* for some reason smaller sector sizes do not appear to work */
	num_entries = (sector_size - 0x300) / sizeof(uint16_t);

	table = calloc(1, sizeof(struct wbfs_table) + (sector_size - 0x300));
	if(!table) {
	    log_error(log_level, "mark_used: failed to allocate wbfs table\n");
	    return 1;
	}
	table->sector_size = sector_size;
	table->num_entries = num_entries;
	*t = table;
    }

    if(!len) return 0;

    sector_size = table->sector_size;
    last_sector = (start_offset + len - 1) / sector_size;
    
    while(last_sector * sizeof(uint16_t) + 0x300 > sector_size) {
	sector_size <<= 1;
	if(!sector_size) {
	    log_error(log_level, "mark_used: wbfs sector size grown over 32 bits\n");
	    free(table);
	    *t = NULL;
	    return 1;
	}
    	last_sector = (start_offset + len - 1) / sector_size;
    }
    if(sector_size != table->sector_size) {
	unsigned int i, j, step;
	num_entries = (sector_size - 0x300) / sizeof(uint16_t);

	log_debug(log_level, "mark_used: growing sector_size: %x -> %x\n", table->sector_size, sector_size);

	table = realloc(*t, sizeof(struct wbfs_table) + (sector_size - 0x300));
	if(!table) {
	    log_error(log_level, "mark_used: failed to grow wbfs table\n");
	    free(*t);
	    *t = NULL;
	    return 1;
	}

	*t = table;

	step = sector_size / table->sector_size;
	for(i=0; i<table->num_entries / step; i++) {
	    table->sec_table[i] = table->sec_table[i*step];
	    for(j=1; j<step; j++)
		table->sec_table[i] |= table->sec_table[i*step+j];
	}

	for(;i<num_entries; i++)
	    table->sec_table[i] = 0;

	table->sector_size = sector_size;
	table->num_entries = num_entries;
    }

    first_sector = start_offset / sector_size;

    for(;first_sector <= last_sector; first_sector++)
	table->sec_table[first_sector] |= 1;

    return 0;
}


#define to_data_size_off(off, sz) p->data_offset + ((off) / 0x7c00 * 0x8000), ((((((off) % 0x7c00) + (sz)) / 0x7c00) + ((((off) % 0x7c00) + (sz)) % 0x7c00 != 0)) * 0x8000)

static int mark_data_used(struct wbfs_table **t, struct partition_data *p, off_t data_offset, off_t data_len, uint8_t log_level) {
    return mark_used(t, to_data_size_off(data_offset, data_len), log_level);
}


int mark_partition_used(struct wbfs_table **t, wiiso_t disc, uint32_t partition) {
    struct partition_data *p = &disc->partitions[partition];
    uint32_t i;

    if(mark_used(t, p->offset_to_partition, sizeof(struct _part_header), disc->log_level) ||
       mark_used(t, p->crt_offset, p->crt_size, disc->log_level)                          ||
       mark_used(t, p->h3_offset, 0x18000, disc->log_level)                               ||
       mark_used(t, p->tmd_offset, p->tmd_size, disc->log_level)                          ||
       mark_data_used(t, p, p->fst_offset, p->fst_size, disc->log_level)                  ||
       mark_data_used(t, p, p->dol_offset, p->dol_size, disc->log_level)                  ||
       mark_data_used(t, p, p->apl_offset, p->apl_size1 + p->apl_size2, disc->log_level))
	return 1;

    for(i=0; i<p->fst_files; i++) {
	off_t foffset;
	uint32_t fsize;

	if(get_file_by_id(disc, partition, i, NULL, &foffset, &fsize, NULL)) {
	    log_warning(disc->log_level, "set_partition_used: bad file %u\n", i);
	    return 1;
	}
	if(!foffset || !fsize)
	    continue;

	if(mark_data_used(t, p, foffset, fsize, disc->log_level))
	    return 1;
    }

    return 0;
}


int copy_disc_data(wiiso_t disc, off_t start_offset, off_t len, const char *file, FILE *of, off_t *last_written) {
    off_t cur_sector = start_offset / 0x8000;
    off_t end_sector = (start_offset + len - 1) / 0x8000;

    if(!len)
	return 0;

    for(;cur_sector <= end_sector; cur_sector++) {
	if(last_written) {
	    if(cur_sector == *last_written)
		continue;
	    *last_written = cur_sector;
	}
	if(disc_iso_read(disc, cur_sector * 0x8000, &disc->raw_sector, sizeof(disc->raw_sector))) {
	    log_error(disc->log_level, "disc_copy_data: failed to read data at offset %llx\n", (unsigned long long)(cur_sector * 0x8000));
	    fclose(of);
	    unlink(file);
	    return 1;
	}
	fseeko(of, cur_sector * 0x8000, SEEK_SET);
	if(fwrite(&disc->raw_sector, sizeof(disc->raw_sector), 1, of) != 1) {
	    log_error(disc->log_level, "disc_copy_data: failed to write data at offset %llx\n", (unsigned long long)(cur_sector * 0x8000)); /* FIXME strerror */
	    fclose(of);
	    unlink(file);
	    return 1;
	}
    }
    return 0;
}


int copy_partition_data(wiiso_t disc, uint32_t partition, const char *file, FILE *of) {
    struct partition_data *p = &disc->partitions[partition];
    off_t last_written = -1;
    uint32_t i;

    if(copy_disc_data(disc, p->offset_to_partition, sizeof(struct _part_header), file, of, &last_written) ||
       copy_disc_data(disc, p->crt_offset, p->crt_size, file, of, &last_written) ||
       copy_disc_data(disc, p->h3_offset, 0x18000, file, of, &last_written) ||
       copy_disc_data(disc, p->tmd_offset, p->tmd_size, file, of, &last_written) ||
       copy_disc_data(disc, to_data_size_off(p->apl_offset, p->apl_size1 + p->apl_size2), file, of, &last_written) ||
       copy_disc_data(disc, to_data_size_off(p->dol_offset, p->dol_size), file, of, &last_written) ||
       copy_disc_data(disc, to_data_size_off(p->fst_offset, p->fst_size), file, of, &last_written))
	return 1;

    for(i=0; i<p->fst_files; i++) {
	off_t foffset;
	uint32_t fsize;
	char *name;

	if(get_file_by_id(disc, partition, i, &name, &foffset, &fsize, NULL)) {
	    log_warning(disc->log_level, "set_partition_used: bad file %u\n", i);
	    return 1;
	}
	if(!foffset || !fsize)
	    continue;

	if(copy_disc_data(disc, to_data_size_off(foffset, fsize), file, of, &last_written))
	    return 1;
    }

    return 0;
}
