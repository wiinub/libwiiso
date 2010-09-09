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
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <openssl/ssl.h>

#include "wiiso.h"
#include "disc.h"
#include "common.h"
#include "log.h"

static int ssl_initted = 0;

#define fail_if_closed() do { if(!is_open(disc)) { log_error(disc->log_level, "%s: disc is closed\n", __FUNCTION__); return 1; } } while(0)

static void reset_disc(wiiso_t disc) {
    memset(disc->f, 0, sizeof(disc->f));
    disc->type = DISC_UNKNOWN;
    disc->split_parts = 0;
    disc->wbfs_table = NULL;
    disc->wbfs_table_entries = 0;
    disc->split_parts = 0;
    disc->num_partitions = 0;
    disc->partitions = NULL;
    disc->last_plain_sector = -1;
}


wiiso_t wiiso_new(enum WIISO_LOGLEVEL log_level) {
    wiiso_t disc = malloc(sizeof(struct _wiiso_int));
    if(disc)
	reset_disc(disc);
    disc->log_level = log_level;
    return disc;
}


int wiiso_free(wiiso_t disc) {
    if(is_open(disc))
	wiiso_close(disc);

    free(disc);
    return 0;
}


static void close_disc(wiiso_t disc) {
    unsigned int i;
    for(i=0; i<disc->split_parts; i++)
	if(disc->f[i])
	    fclose(disc->f[i]);

    if(disc->wbfs_table)
	free(disc->wbfs_table);

    if(disc->partitions) {
	for(i=0; i<disc->num_partitions; i++) {
	    if(disc->partitions[i].cert_chain)
		crtmgr_destroy(disc->partitions[i].cert_chain);
	    if(disc->partitions[i].fst)
		free(disc->partitions[i].fst);
	}
	free(disc->partitions);
    }
    reset_disc(disc);
}


int wiiso_open(wiiso_t disc, const char *file) {
    char buf[256];
    int i;
    FILE *f;

    if(!ssl_initted) {
	SSL_load_error_strings();
	ssl_initted |= 1;
    }

    if(is_open(disc)) {
	log_error(disc->log_level, "wiiso_open: already open\n");
	return 1;
    }

    if(strlen(file) >= sizeof(disc->filename)) {
	log_error(disc->log_level, "wiiso_open: file name too long\n");
	return 1;
    }

    f = fopen(file, "rb");
    if(!f) {
	strerror_r(errno, buf, sizeof(buf));
	log_error(disc->log_level, "wiiso_open: failed to open file %s (%s)\n", file, buf);
	return 1;
    }

    if(fread(buf, 4, 1, f) != 1) {
	log_error(disc->log_level, "wiiso_open: failed to read magic from file %s\n", file);
	return 1;
    }

    strcpy(disc->filename, file);
    disc->f[0] = f;

    i = 1;
    if(!memcmp(buf, "WBFS", 4) && (i = read_wbfs_header(disc))) {
	disc->f[0] = NULL;
	close_disc(disc);
	disc->f[0] = f;
    }

    if(i)
	i = read_iso_header(disc);

    if(i) {
	close_disc(disc);
	log_error(disc->log_level, "wiiso_open: unable to determine image type of file %s\n", file);
	return 1;
    }

    return 0;
}


int wiiso_close(wiiso_t disc) {
    if(!is_open(disc)) {
	log_error(disc->log_level, "wiiso_close: already closed\n");
	return 1;
    }

    close_disc(disc);
    return 0;
}


int wiiso_partition_count(wiiso_t disc, unsigned int *number_of_partitions) {
    fail_if_closed();
    *number_of_partitions = disc->num_partitions;
    return 0;
}


int wiiso_verify(wiiso_t disc, unsigned int partition_number, int verify_all_data) {
    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_verify: bad partition number\n");
	return 1;
    }
    return verify_partition(disc, partition_number, verify_all_data);
}


int wiiso_get_file_count(wiiso_t disc, unsigned int partition_number, unsigned int *number_of_files) {
    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_verify: bad partition number\n");
	return 1;
    }

    *number_of_files = disc->partitions[partition_number].fst_files;
    return 0;
}


int wiiso_get_file_name(wiiso_t disc, unsigned int partition_number, unsigned int file_id, char *buf, unsigned int buf_len) {
    unsigned int file_len, file_parent, avail_len = buf_len;
    off_t file_offset;
    char *file_name;
    int len;

    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_get_file_name: bad partition number\n");
	return 1;
    }

    if(get_file_by_id(disc, partition_number, file_id, &file_name, &file_offset, &file_len, &file_parent)) {
	log_error(disc->log_level, "wiiso_get_file_name: bad file id\n");
	return 1;
    }

    do {
	len = strlen(file_name);
	if(len + 1 >= avail_len) {
	    log_error(disc->log_level, "wiiso_get_file_name: buffer too small\n");
	    return 1;
	}
	memcpy(buf + avail_len - len, file_name, len);
	buf[avail_len - len - 1] = '/';
	avail_len -= len + 1;
	file_id = file_parent;
	if(get_file_by_id(disc, partition_number, file_id, &file_name, NULL, NULL, &file_parent)) {
	    log_error(disc->log_level, "wiiso_get_file_name: bad FST tree\n");
	    return 1;
	}
    } while(file_id);

    memmove(buf, &buf[avail_len], buf_len - avail_len);
    buf[buf_len - avail_len] = '\0';

    return 0;
}


int wiiso_get_file_id(wiiso_t disc, unsigned int partition_number, const char *full_path, unsigned int *file_id) {
    struct partition_data *p = &disc->partitions[partition_number];
    unsigned int i, fullname_len;
    char *ref_name;

    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_get_file_id: bad partition number\n");
	return 1;
    }

    fullname_len = strlen(full_path);
    ref_name = strrchr(full_path, '/');
    if(!ref_name || *full_path!='/' || fullname_len < 1) {
	log_error(disc->log_level, "wiiso_get_file_id: not invoked with a full path name\n");
	return 1;
    }
    ref_name++;

    for(i=0; i<p->fst_files; i++) {
	unsigned int file_parent;
	char *file_name, *curpath;

	if(get_file_by_id(disc, partition_number, i, &file_name, NULL, NULL, &file_parent)) {
	    log_error(disc->log_level, "wiiso_get_file_id: bad FST tree\n");
	    return 1;
	}
	/* if(!file_offset) continue; */
	if(strcmp(file_name, ref_name)) continue;
	curpath = ref_name;
	do {
	    unsigned int parent_len;
	    if(!file_parent && curpath == full_path + 1) {
		*file_id = i;
		return 0;
	    }
	    get_file_by_id(disc, partition_number, file_parent, &file_name, NULL, NULL, &file_parent);

	    parent_len = strlen(file_name);
	    curpath -= 2 + parent_len;
	    if(curpath < full_path || *curpath != '/')
		break;
	    curpath++;
	    if(memcmp(curpath, file_name, parent_len))
		break;
	} while(1);
	
    }
    log_debug(disc->log_level, "wiiso_get_file_id: file '%s' not found in partition %u\n", full_path, partition_number);
    return 1;
}


int wiiso_get_file_size(wiiso_t disc, unsigned int partition_number, unsigned int file_id, unsigned int *file_size) {

    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_get_file_size: bad partition number\n");
	return 1;
    }

    if(get_file_by_id(disc, partition_number, file_id, NULL, NULL, file_size, NULL)) {
	log_error(disc->log_level, "wiiso_get_file_size: bad file id\n");
	return 1;
    }

    return 0;
}


int wiiso_get_dol_size(wiiso_t disc, unsigned int partition_number, off_t *file_size) {

    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_get_dol_size: bad partition number\n");
	return 1;
    }

    *file_size = disc->partitions[partition_number].dol_size;
    return 0;
}


int wiiso_extract_file(wiiso_t disc, unsigned int partition_number, unsigned int file_id, const char *output_file) {
    unsigned int file_size;
    off_t file_offset;
    char buf[4096];
    FILE *of;

    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_extract_file: bad partition number\n");
	return 1;
    }

    if(get_file_by_id(disc, partition_number, file_id, NULL, &file_offset, &file_size, NULL)) {
	log_error(disc->log_level, "wiiso_extract_file: bad file id\n");
	return 1;
    }

    if(!file_offset) {
	log_error(disc->log_level, "wiiso_extract_file: file %u is a directory\n", file_id);
	return 1;
    }

    of = fopen(output_file, "w");
    if(!of) {
	strerror_r(errno, buf, sizeof(buf));
	log_error(disc->log_level, "wiiso_extract_file: failed to open file %s for writing: %s\n", output_file, buf);
	return 1;
    }

    while(file_size) {
	unsigned int todo = MIN(file_size, sizeof(buf));
	if(read_data(disc, partition_number, file_offset, todo, buf, NULL)) {
	    log_error(disc->log_level, "wiiso_extract_file: read failed\n");
	    fclose(of);
	    unlink(output_file);
	    return 1;
	}
	if(fwrite(buf, todo, 1, of) != 1) {
	    strerror_r(errno, buf, sizeof(buf));
	    log_error(disc->log_level, "wiiso_extract_file: write failed: %s\n", buf);
	    fclose(of);
	    unlink(output_file);
	    return 1;
	}
	file_size -= todo;
	file_offset += todo;
    }

    fclose(of);
    return 0;
}


int wiiso_extract_dol(wiiso_t disc, unsigned int partition_number, const char *output_file) {
    off_t file_size;
    off_t file_offset;
    char buf[4096];
    FILE *of;

    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_extract_dol: bad partition number\n");
	return 1;
    }

    file_offset = disc->partitions[partition_number].dol_offset;
    file_size = disc->partitions[partition_number].dol_size;
    of = fopen(output_file, "w");
    if(!of) {
	strerror_r(errno, buf, sizeof(buf));
	log_error(disc->log_level, "wiiso_extract_dol: failed to open file %s for writing: %s\n", output_file, buf);
	return 1;
    }

    while(file_size) {
	unsigned int todo = MIN(file_size, sizeof(buf));
	if(read_data(disc, partition_number, file_offset, todo, buf, NULL)) {
	    log_error(disc->log_level, "wiiso_extract_dol: read failed\n");
	    fclose(of);
	    unlink(output_file);
	    return 1;
	}
	if(fwrite(buf, todo, 1, of) != 1) {
	    strerror_r(errno, buf, sizeof(buf));
	    log_error(disc->log_level, "wiiso_extract_dol: write failed: %s\n", buf);
	    fclose(of);
	    unlink(output_file);
	    return 1;
	}
	file_size -= todo;
	file_offset += todo;
    }

    fclose(of);
    return 0;
}


static int to_be_skipped(wiiso_t disc, unsigned int part, int filter) {
    switch(disc->partitions[part].partition_type) {
    case 0:
	if(!(filter & WIISO_PART_DATA))
	    return 1;
	return 0;
    case 1:
	if(!(filter & WIISO_PART_UPDATE))
	    return 1;
	return 0;
    case 2:
	if(!(filter & WIISO_PART_CHANNEL))
	    return 1;
	return 0;
    default:
	if(!(filter & WIISO_PART_UNKNOWN))
	    return 1;
    }
    return 0;
}


struct _wbfs_wrt {
    FILE *of[MAX_SPLIT_PARTS];
    char *filename[MAX_SPLIT_PARTS];
    off_t split_size;
};


static void wbfs_wrt_free(struct _wbfs_wrt *wbfs_wrt, int rm) {
    unsigned int i;

    for(i=0; i<MAX_SPLIT_PARTS; i++) {
	if(wbfs_wrt->of[i])
	    fclose(wbfs_wrt->of[i]);
	if(wbfs_wrt->filename[i]) {
	    if(rm)
		unlink(wbfs_wrt->filename[i]);
	    if(i)
		free(wbfs_wrt->filename[i]);
	}
    }
}


static int write_wbfs_part(const void *data, off_t len, off_t offset, struct _wbfs_wrt *wbfs_wrt, uint8_t log_level) {
    unsigned int first_part = 0, last_part = 0;
    char buf[256];

    if(wbfs_wrt->split_size) {
	off_t tail = len;
	while(offset >= wbfs_wrt->split_size) {
	    first_part++;
	    offset -= wbfs_wrt->split_size;
	}
	last_part = first_part;
	while(offset + tail > wbfs_wrt->split_size) {
	    last_part++;
	    tail -= wbfs_wrt->split_size;
	}
	if(last_part>=MAX_SPLIT_PARTS) {
	    log_error(log_level, "write_wbfs_part: too many parts\n");
	    wbfs_wrt_free(wbfs_wrt, 1);
	    return 1;
	}
    }

    for(;first_part <= last_part; first_part++) {
	off_t todo;
	if(!wbfs_wrt->of[first_part]) {
	    if(first_part) {
		unsigned int fnamelen = strlen(wbfs_wrt->filename[0]);
		wbfs_wrt->filename[first_part] = malloc(fnamelen+1);
		if(!wbfs_wrt->filename[first_part]) {
		    log_error(log_level, "write_wbfs_part: strdup failed on '%s'\n", wbfs_wrt->filename[0]);
		    wbfs_wrt_free(wbfs_wrt, 1);
		    return 1;
		}
		memcpy(wbfs_wrt->filename[first_part], wbfs_wrt->filename[0], fnamelen - 1);
		wbfs_wrt->filename[first_part][fnamelen - 1] = '0' + first_part;
		wbfs_wrt->filename[first_part][fnamelen] = '\0';
	    }
	    if(!(wbfs_wrt->of[first_part] = fopen(wbfs_wrt->filename[first_part], "w"))) {
		strerror_r(errno, buf, sizeof(buf));
		log_error(log_level, "write_wbfs_part: failed to open %s for writing: %s\n", wbfs_wrt->filename[first_part], buf);
		wbfs_wrt_free(wbfs_wrt, 1);
		return 1;
	    }
	    log_debug(log_level, "write_wbfs_part: created part file %s\n", wbfs_wrt->filename[first_part]);
	}

	todo = wbfs_wrt->split_size ? MIN(len, wbfs_wrt->split_size - offset) : len;
	fseeko(wbfs_wrt->of[first_part], offset, SEEK_SET);
	if(fwrite(data, todo, 1, wbfs_wrt->of[first_part]) != 1) {
	    strerror_r(errno, buf, sizeof(buf));
	    log_error(log_level, "write_wbfs_part: failed to write to %s: %s\n", wbfs_wrt->filename[first_part], buf);
	    wbfs_wrt_free(wbfs_wrt, 1);
	    return 1;
	}
	offset = 0;
	len -= todo;
	data = (uint8_t *)data + todo;
    }
    return 0;
}


int wiiso_save_wbfs(wiiso_t disc, const char *output_file, int type_filter, off_t split_size) {
    static const uint8_t de_bruijn[] = { 0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9};
    uint8_t wbfshdr[16] = "WBFSaCaB\x09\x00\x00\x00\x01\x00\x00\x00", *sector;
    struct wbfs_table *wtbl = NULL;
    unsigned int i, k, todump = 0;
    struct _wbfs_wrt wbfs_wrt;

    fail_if_closed();

    for(i=0; i<disc->num_partitions; i++) {
	if(to_be_skipped(disc, i, type_filter))
	    continue;
	todump++;
	if(mark_partition_used(&wtbl, disc, i)) {
	    log_error(disc->log_level, "wiiso_save_wbfs: failed to mark partition %u as used\n", i);
	    return 1;
	}
    }

    if(mark_used(&wtbl, 0, sizeof(struct iso_header), disc->log_level)) {
	log_error(disc->log_level, "wiiso_save_wbfs: failed to mark iso header as used\n");
	return 1;
    }

    if(mark_used(&wtbl, 0x40000, 0x8000 * 2, disc->log_level)) {
	log_error(disc->log_level, "wiiso_save_wbfs: failed to mark partition table as used\n");
	return 1;
    }

    if(mark_used(&wtbl, disc->off_to_part_tbl, 8*todump, disc->log_level)) {
	log_error(disc->log_level, "wiiso_save_wbfs: failed to mark partition table as used\n");
	return 1;
    }

    if(!(sector = malloc(wtbl->sector_size))) {
	log_error(disc->log_level, "wiiso_save_wbfs: out of memory when allocating read/write buffer (%u bytes)\n", wtbl->sector_size);
	free(wtbl);
	return 1;
    }

    memset(&wbfs_wrt, 0, sizeof(wbfs_wrt));
    wbfs_wrt.split_size = split_size;
    wbfs_wrt.filename[0] = (char *)output_file;

    for(i=0, k=1; i<wtbl->num_entries; i++) {
	if(!wtbl->sec_table[i])
	    continue;

	wtbl->sec_table[i] = htons(k);

	if(disc_iso_read_with_blanks(disc, (off_t)i * wtbl->sector_size, sector, wtbl->sector_size, 1)) {
	    log_error(disc->log_level, "wiiso_save_wbfs: failed to read entry %x (sector %llx)\n", i, (unsigned long long)i * wtbl->sector_size);
	    wbfs_wrt_free(&wbfs_wrt, 1);
	    free(sector);
	    free(wtbl);
	    return 1;
	}

	if(write_wbfs_part(sector, wtbl->sector_size, (off_t)k * wtbl->sector_size, &wbfs_wrt, disc->log_level)) {
	    free(sector);
	    free(wtbl);
	    return 1;
	}

	if(!i && write_wbfs_part(sector, 0x100, 0x200, &wbfs_wrt, disc->log_level)) {
	    free(sector);
	    free(wtbl);
	    return 1;
	}
	k++;
    }

    if(write_wbfs_part(wtbl->sec_table, wtbl->num_entries * sizeof(uint16_t), 0x300, &wbfs_wrt, disc->log_level)) {
	free(sector);
	free(wtbl);
	return 1;
    }

    split_size = k;
    split_size *= wtbl->sector_size;
    split_size /= 0x200;
    wbfshdr[4] = split_size>>24;
    wbfshdr[5] = split_size>>16;
    wbfshdr[6] = split_size>>8;
    wbfshdr[7] = split_size;

    wbfshdr[9] = de_bruijn[(wtbl->sector_size * 0x077cb531) >> 27];

    if(write_wbfs_part(wbfshdr, 16, 0, &wbfs_wrt, disc->log_level)) {
	free(sector);
	free(wtbl);
	return 1;
    }

    if(todump != disc->num_partitions) {
	struct _uint_pair uint_pair;
	off_t part_tbl = ntohs(wtbl->sec_table[0x40000 / wtbl->sector_size]);
	part_tbl *= wtbl->sector_size;
	part_tbl += 0x40000 % wtbl->sector_size;
	uint_pair.uint0 = htonl(todump);

 	if(write_wbfs_part(&uint_pair.uint0, sizeof(uint_pair.uint0), part_tbl, &wbfs_wrt, disc->log_level)) {
	    free(sector);
	    free(wtbl);
	    return 1;
	}

	part_tbl = ntohs(wtbl->sec_table[disc->off_to_part_tbl / wtbl->sector_size]);
	part_tbl *= wtbl->sector_size;
	part_tbl += disc->off_to_part_tbl % wtbl->sector_size;

	for(i=0; i<disc->num_partitions; i++) {
	    if(to_be_skipped(disc, i, type_filter))
		continue;

	    uint_pair.uint0 = htonl(disc->partitions[i].offset_to_partition >> 2);
	    uint_pair.uint1 = htonl(disc->partitions[i].partition_type);

	    if(write_wbfs_part(&uint_pair, sizeof(uint_pair), part_tbl, &wbfs_wrt, disc->log_level)) {
		free(sector);
		free(wtbl);
		return 1;
	    }
	    part_tbl += sizeof(uint_pair);
	}
    }

    wbfs_wrt_free(&wbfs_wrt, 0);
    free(sector);
    free(wtbl);

    return 0;
}


int wiiso_save_iso(wiiso_t disc, const char *output_file, int type_filter) {
    unsigned int i, todump = 0;
    struct _uint_pair uint_pair;
    char buf[256];
    FILE *of;

    fail_if_closed();

    if(!(of=fopen(output_file, "w"))) {
	strerror_r(errno, buf, sizeof(buf));
	log_error(disc->log_level, "wiiso_save_wbfs: failed to open %s for writing: %s\n", output_file, buf);
	return 1;
    }

    if(copy_disc_data(disc, 0, sizeof(struct iso_header), output_file, of, NULL))
	return 1;

    for(i=0; i<disc->num_partitions; i++) {
	if(to_be_skipped(disc, i, type_filter))
	    continue;
	todump++;

	if(copy_partition_data(disc, i, output_file, of))
	    return 1;
    }

    if(disc_iso_read(disc, 0x40000, &disc->raw_sector, sizeof(disc->raw_sector))) {
	log_error(disc->log_level, "wiiso_save_iso: failed to read data at offset %x\n", 0x40000);
	fclose(of);
	unlink(output_file);
	return 1;
    }
    uint_pair.uint0 = htonl(todump);
    memcpy(&disc->raw_sector, &uint_pair.uint0, sizeof(uint_pair.uint0));
    fseeko(of, 0x40000, SEEK_SET);
    if(fwrite(&disc->raw_sector, sizeof(disc->raw_sector), 1, of) != 1) {
	strerror_r(errno, buf, sizeof(buf));
	log_error(disc->log_level, "wiiso_save_iso: failed to write data at offset %x: %s\n", 0x40000, buf);
	fclose(of);
	unlink(output_file);
	return 1;
    }
    if(copy_disc_data(disc, 0x48000, sizeof(struct iso_header), output_file, of, NULL))
	return 1;

    fseeko(of, disc->off_to_part_tbl, SEEK_SET);
    for(i=0; i<disc->num_partitions; i++) {
	if(to_be_skipped(disc, i, type_filter))
	    continue;
	uint_pair.uint0 = htonl(disc->partitions[i].offset_to_partition >> 2);
	uint_pair.uint1 = htonl(disc->partitions[i].partition_type);
	if(!(fwrite(&uint_pair, sizeof(uint_pair), 1, of))) {
	    strerror_r(errno, buf, sizeof(buf));
	    log_error(disc->log_level, "wiiso_save_iso: failed to write data at offset %llx: %s\n", (unsigned long long)(disc->off_to_part_tbl + i * 8), buf);
	    fclose(of);
	    unlink(output_file);
	    return 1;
	}
    }

    fclose(of);
    return 0;
}


int wiiso_get_partition_name(wiiso_t disc, unsigned int partition_number, const char **partition_name) {
    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_get_partition_name: bad partition number\n");
	return 1;
    }

    *partition_name = disc->partitions[partition_number].partition_header.name;
    return 0;
}


int wiiso_get_partition_id(wiiso_t disc, unsigned int partition_number, const char **partition_id) {
    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_get_partition_id: bad partition number\n");
	return 1;
    }

    *partition_id = disc->partitions[partition_number].partition_header.id;
    return 0;
}


int wiiso_get_partition_type(wiiso_t disc, unsigned int partition_number, const char **partition_type) {
    fail_if_closed();

    if(partition_number >= disc->num_partitions) {
	log_error(disc->log_level, "wiiso_get_partition_type: bad partition number\n");
	return 1;
    }

    *partition_type = part_type(disc->partitions[partition_number].partition_type);
    return 0;
}


int wiiso_get_disc_name(wiiso_t disc, const char **disk_name) {
    fail_if_closed();

    *disk_name = disc->iso_header.name;
    return 0;
}


int wiiso_get_disc_id(wiiso_t disc, const char **disk_id) {
    fail_if_closed();

    *disk_id = disc->iso_header.id;
    return 0;
}
