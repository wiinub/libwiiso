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

#ifndef _WIISO_H
#define _WIISO_H

#include <unistd.h>

enum WIISO_TYPE { DISC_UNKNOWN, DISC_ISO, DISC_WBFS };
#define WIISO_PART_DATA 1
#define WIISO_PART_UPDATE 2
#define WIISO_PART_CHANNEL 4
#define WIISO_PART_UNKNOWN 8
#define WIISO_PART_ANY (WIISO_PART_DATA|WIISO_PART_UPDATE|WIISO_PART_CHANNEL|WIISO_PART_UNKNOWN)

enum WIISO_LOGLEVEL {
    WIISO_LOG_NONE,
    WIISO_LOG_ERR,
    WIISO_LOG_WARN,
    WIISO_LOG_DEBUG
};

struct _wiiso_int;
typedef struct _wiiso_int *wiiso_t;


/* Create and initialize a disc */
wiiso_t wiiso_new(enum WIISO_LOGLEVEL log_level);


/* NOTE: all the follwoing functions return 0 on success. */

/* Open a disc image (iso or wbfs) */
int wiiso_open(wiiso_t disc, const char *file);

/* Close a disc image */
int wiiso_close(wiiso_t disc);

/* Release the disc */
int wiiso_free(wiiso_t disc);

/* Return the name of the disc */
int wiiso_get_disc_name(wiiso_t disc, const char **constdisk_name);

/* Return the id of the disc */
int wiiso_get_disc_id(wiiso_t disc, const char **disk_id);

/* Return the number of partitions in an open disc */
int wiiso_partition_count(wiiso_t disc, unsigned int *number_of_partitions);

/* Return the name of the partition */
int wiiso_get_partition_name(wiiso_t disc, unsigned int partition_number, const char **partition_name);

/* Return the id of the partition */
int wiiso_get_partition_id(wiiso_t disc, unsigned int partition_number, const char **partition_id);

/* Return the type of the partition */
int wiiso_get_partition_type(wiiso_t disc, unsigned int partition_number, const char **partition_type);

/* Return the number of files in a partition */
int wiiso_get_file_count(wiiso_t disc, unsigned int partition_number, unsigned int *number_of_files);

/* Return the name of a file */
int wiiso_get_file_name(wiiso_t disc, unsigned int partition_number, unsigned int file_id, char *buf, unsigned int buf_len);

/* Return the id of a file */
int wiiso_get_file_id(wiiso_t disc, unsigned int partition_number, const char *full_path, unsigned int *file_id);

/* Return the size of a file */
int wiiso_get_file_size(wiiso_t disc, unsigned int partition_number, unsigned int file_id, unsigned int *file_size);

/* Extract a file */
int wiiso_extract_file(wiiso_t disc, unsigned int partition_number, unsigned int file_id, const char *output_file);

/* Return the size of a file */
int wiiso_get_dol_size(wiiso_t disc, unsigned int partition_number, off_t *file_size);

/* Extract a file */
int wiiso_extract_dol(wiiso_t disc, unsigned int partition_number, const char *output_file);

/* Verify the partition data. If verify_all_data is nonzero even unused sectors are checked, which of course doesn't work with scrubbed files */
int wiiso_verify(wiiso_t disc, unsigned int partition_number, int verify_all_data);

/* Save a disc to a (scrubbed) iso image. The type_filter is one of the WIISO_PART_* defined above */
int wiiso_save_iso(wiiso_t disc, const char *output_file, int type_filter);

/* Save a disc to a wbfs image. If split_size is 0, the output is a single wbfs file */
int wiiso_save_wbfs(wiiso_t disc, const char *output_file, int type_filter, off_t split_size);

#endif
