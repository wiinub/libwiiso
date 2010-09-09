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


#ifndef _DISC_H
#define _DISC_H

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "wiiso.h"
#include "crtmgr.h"

struct _uint_pair {
    uint32_t uint0;
    uint32_t uint1;
};

struct iso_header {
    char id[6];
    char id_term;
    char pad1[0x11];
    uint32_t magic;
    char pad2[4];
    char name[64];
    char name_term;
};

struct partition_data {
    off_t offset_to_partition;
    uint8_t plain_title_key[16];
    uint32_t partition_type;
    uint32_t can_be_verified;

    off_t data_offset, data_size;

    off_t fst_offset;
    off_t fst_size;
    off_t dol_offset;
    off_t dol_size;
    off_t apl_offset;
    off_t apl_size1;
    off_t apl_size2;

    off_t tmd_offset;
    off_t crt_offset;
    off_t h3_offset;
    uint32_t tmd_size;
    uint32_t crt_size;

    uint8_t *fst;
    uint32_t fst_files;

    uint8_t h4[20];

    struct crtmgr *cert_chain;
    struct iso_header partition_header;

    struct h3 {
	uint8_t sha1[0x1333][20];
	uint8_t pad[4];
    } h3;

};

struct sector_header {
    uint8_t h0[31][20];
    uint8_t pad0[20];
    uint8_t h1[8][20];
    uint8_t pad1[32];
    uint8_t h2[8][20];
    uint8_t pad2[32];
};

union sector_data {
    uint8_t chunk[31][0x400];
    uint8_t raw[31*0x400];
};


struct sector {
    struct sector_header header;
    union sector_data data;
};

struct _part_header {
    struct TICKET {
	uint8_t sig_type[4];
	uint8_t signature[0x100];
	uint8_t pad0[0x3c];
	uint8_t issuer[0x40];
	uint8_t unk0[0x3f];
	uint8_t encrypted_key[0x10];
	uint8_t unk1;
	uint8_t ticket_id[8];
	uint8_t console_id[4];
	uint8_t title_id[8];
	uint8_t unk2[2];
	uint8_t dlc_content[3];
	uint8_t unk3[8];
	uint8_t common_key_id;
	uint8_t unk4[0x30];
	uint8_t unk5[0x20];
	uint8_t pad1[2];
	uint8_t time_limit_enabled[4];
	uint8_t time_limit[4];
	uint8_t pad2[0x58];
    } ticket;
    uint32_t tmd_size;
    uint32_t tmd_offset;
    uint32_t crt_size;
    uint32_t crt_offset;
    uint32_t h3_offset;
    uint32_t data_offset;
    uint32_t data_size;
};

#define MAX_SPLIT_PARTS 8
struct _wiiso_int {
    char filename[4096];
    enum WIISO_TYPE type;
    unsigned int split_parts;
    FILE *f[MAX_SPLIT_PARTS];
    off_t split_part_sizes[MAX_SPLIT_PARTS];

    off_t off_to_part_tbl;
    struct iso_header iso_header;

    uint32_t wbfs_table_entries;
    uint16_t *wbfs_table;
    uint16_t wbfs_table_max;
    uint32_t wbfs_sector_size;
    uint32_t wbfs_header_sects;

    uint32_t num_partitions;
    struct partition_data *partitions;

    struct sector raw_sector;
    struct sector plain_sector;
    off_t last_plain_sector;
    int last_verified;
    char safe_issuer[0x41];
    uint8_t log_level;
    char log_buffer[1024];
};


struct wbfs_table {
    uint32_t sector_size;
    uint32_t num_entries;
    uint16_t sec_table[];
} *wtbl_t;



int is_open(wiiso_t disc);
int read_iso_header(wiiso_t disc);
int read_wbfs_header(wiiso_t disc);
int verify_partition(wiiso_t disc, uint32_t partition, int verify_all_data);
int get_file_by_id(wiiso_t disc, uint32_t partition, uint32_t id, char **file_name, off_t *file_offset, uint32_t *file_len, uint32_t *file_parent);
int disc_iso_read(wiiso_t disc, off_t iso_offset, void *dest, off_t len);
int disc_iso_read_with_blanks(wiiso_t disc, off_t iso_offset, void *dest, off_t len, int with_blanks);
int read_data(wiiso_t disc, uint32_t partition, off_t data_offset, off_t data_len, void *dest, int *verified);
int mark_used(struct wbfs_table **t, off_t start_offset, off_t len, uint8_t log_level);
int mark_partition_used(struct wbfs_table **t, wiiso_t disc, uint32_t partition);
int copy_disc_data(wiiso_t disc, off_t start_offset, off_t len, char const *file, FILE *of, off_t *last_written);
int copy_partition_data(wiiso_t disc, uint32_t partition, const char *file, FILE *of);
const char *part_type(uint32_t type);

#endif /* _DISC_H */
