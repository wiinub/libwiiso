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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>

#include "wiiso.h"

typedef int (*cmd_func)(wiiso_t, int, char **);
static int disc_info(wiiso_t, int, char **);
static int list_partitions(wiiso_t, int, char **);
static int write_iso(wiiso_t, int, char **);
static int write_wbfs(wiiso_t, int, char **);
static int list_files(wiiso_t, int, char **);
static int extract_file(wiiso_t, int, char **);


static const struct _commands {
    const char *command;
    const char *brief;
    const char *syntax;
    cmd_func func;
} commands[] = {
    {"iso", "saves the image as iso", "\
[filters] <output file>\n\
filters:\n\
\t-d\tsave data (i.e. game) partitions\n\
\t-u\tsave update partitions\n\
\t-c\tsave channel partitions\n\
\t-k\tsave unknown partitions\n\
\t-a\tsave all partitions (default)\n\
output file: the name of the destination iso image", write_iso},
    {"wbfs", "saves the image as wbfs", "\
[filters] [-s <split size>] [output file]\n\
filters:\n\
\t-d\tsave data (i.e. game) partitions\n\
\t-u\tsave update partitions\n\
\t-c\tsave channel partitions\n\
\t-k\tsave unknown partitions\n\
\t-a\tsave all partitions (default)\n\
split size: maximum size (in MB) of wbfs parts (default: unlimited)\n\
output file: the name of the destination wbfs image (default: GAMEID.wbfs in the work dir)",write_wbfs},
    {"info", "shows basic info about the disc image", "", disc_info},
    {"lsparts", "lists partitions in the disc image", "", list_partitions},
    {"ls", "lists files and directories (fst entries)", "<partition number> [pattern]\npartition number: the partition to list files from\npattern: a filter regex (default: empty, list all files)", list_files},
    {"extract", "extracts a file from a disc partition", "<partition number> <file id | full file path> <output file>\npartition number: the partition to list files from\nfile id: # of the file entry (as reported by ls)\nfull file path: full path to the file to be extracted\noutput file: file to save the extracted content to", extract_file},
    {NULL, NULL, NULL, NULL}
};


static int usage(const char *self, const char *command) {
    unsigned int i;
    printf("usage: %s <iso or wbfs> <command> <params...>\n\ncommands:\n", self);

    for(i=0; commands[i].command; i++) {
	if(command && strcmp(command,  commands[i].command))
	    continue;
	printf("    %-24s%s\n", commands[i].command, commands[i].brief);
	if(!command)
	    continue;
	printf("\ncommand syntax: %s <iso or wbfs> %s %s\n", self, command, commands[i].syntax);
	return 1;
    }
    printf("\nfor help on specific commands: %s <command> --help\n", self);
    return 1;
}


#define FAIL_CMD do { return usage(argv[0], argv[2]); } while(0);
#define GET_PARTCNT						\
    do {							\
	if(wiiso_partition_count(disc, &partcnt)) {		\
	    printf("Failed to retrieve partition count\n");	\
	    return 1;						\
	}							\
    } while(0);


#define GET_PARTNO					\
    do {						\
	unsigned int partcnt;				\
	char *__end;					\
	GET_PARTCNT;					\
	partno = strtol(argv[3], &__end, 0);		\
	if(*__end)					\
	    FAIL_CMD;					\
	if(partno >= partcnt) {				\
	    printf("Partition %u not found\n", partno);	\
	    return 1;					\
	}						\
    } while(0);


static int list_files(wiiso_t disc, int argc, char **argv) {
    unsigned int partno, filecnt, i;
    regex_t *re = NULL, reg;
    char fname[4096];
    if(argc < 4 || argc > 5)
	FAIL_CMD;

    GET_PARTNO;

    if(argc == 5) {
	if(regcomp(&reg, argv[4], REG_EXTENDED|REG_NOSUB)) {
	    printf("Failed to compile regex %s\n", argv[4]);
	    return 1;
	}
	re = &reg;
    }

    if(wiiso_get_file_count(disc, partno, &filecnt)) {
	printf("Ralied to retrieve the file count\n");
	return 1;
    }

    for(i=0; i<filecnt; i++) {
	unsigned int sz;
	if(wiiso_get_file_name(disc, partno, i, fname, sizeof(fname)) || wiiso_get_file_size(disc, partno, i, &sz))
	    printf("%03u: ERROR - Failed to retrieve filename\n", i);
	else if(re && regexec(re, fname, 0, NULL, 0) == REG_NOMATCH)
	    continue;
	printf("%03u: %s\n", i, fname);
    }

    if(re) regfree(re);

    return 0;
}



static int extract_file(wiiso_t disc, int argc, char **argv) {
    unsigned int partno, file_id, file_size;
    char *fname, fnamebuf[4096];
    if(argc != 6)
	FAIL_CMD;

    GET_PARTNO;

    if(*argv[4] == '/') {
	fname = argv[4];
	if(wiiso_get_file_id(disc, partno, fname, &file_id)) {
	    printf("File %s not found in partition %u\n", fname, partno);
	    return 1;
	}
    } else {
	char *end;
	file_id = strtol(argv[4], &end, 0);
	if(*end)
	    FAIL_CMD;
	if(wiiso_get_file_name(disc, partno, file_id, fnamebuf, sizeof(fnamebuf))) {
	    printf("File #%u not found in partition %u\n", file_id, partno);
	    return 1;
	}
	fname = fnamebuf;
    }

    wiiso_get_file_size(disc, partno, file_id, &file_size);
    if(!file_size) {
	printf("The file is either a directory or it's empry.\n");
	return 0;
    }
    printf("Saving %s to %s...\n", fname, argv[5]);
    if(wiiso_extract_file(disc, partno, file_id, argv[5])) {
	printf("Extraction failed\n");
	return 1;
    }
    printf("Extraction complete\n");
    return 0;
}


static int disc_info(wiiso_t disc, int argc, char **argv) {
    const char *id, *title;
    if(argc != 3)
	FAIL_CMD;

    if(wiiso_get_disc_id(disc, &id) || wiiso_get_disc_name(disc, &title)) {
	printf("Failed to retrieve disc info");
	return 1;
    }

    printf("%s (%s)\n", title, id);
    return 0;
}


static int list_partitions(wiiso_t disc, int argc, char **argv) {
    const char *name, *id, *type;
    unsigned int i, partcnt;

    if(argc != 3)
	FAIL_CMD;

    GET_PARTCNT;

    printf("Found %u partitions in the disc\n", partcnt);
    for(i=0; i<partcnt; i++) {
	if(wiiso_get_partition_name(disc, i, &name) || wiiso_get_partition_id(disc, i, &id) || wiiso_get_partition_type(disc, i, &type))
	    printf("%u - Failed to retrieve partition data\n", i);
	else
	    printf("%u - '%s' (%s) - Type: %s\n", i, name, id, type);
    }
    return 0;
}


static int parttype_from_arg(char *arg) {
    int ret=0, len;
    if(arg[0] != '-')
	return -1;
    len = strlen(arg) - 1;
    if(len <= 0)
	return -1;
    for(;len;len--) {
	switch(arg[len]) {
	case 'd':
	    ret |= WIISO_PART_DATA;
	    break;
	case 'u':
	    ret |= WIISO_PART_UPDATE;
	    break;
	case 'c':
	    ret |= WIISO_PART_CHANNEL;
	    break;
	case 'k':
	    ret |= WIISO_PART_UNKNOWN;
	    break;
	case 'a':
	    ret = WIISO_PART_ANY;
	    break;
	default:
	    return -1;
	}
    }
    return ret;
}


static int parttype_from_args(int argc, char **argv) {
    int i, ret=0;

    for(i=3; i<argc; i++)
	ret |= parttype_from_arg(argv[i]);
    if(!ret)
	ret = WIISO_PART_ANY;
    return ret;
}


static int write_iso(wiiso_t disc, int argc, char **argv) {
    int type_filter;
    if(argc < 4 || (type_filter = parttype_from_args(argc-1, argv)) < 0)
	FAIL_CMD;

    printf("Saving iso image to %s...\n", argv[argc-1]);
    if(wiiso_save_iso(disc, argv[argc-1], type_filter)) {
	printf("Failed to save iso file\n");
	return 1;
    }

    printf("Successfully saved iso image to %s\n", argv[argc-1]);
    return 0;
}


static int write_wbfs(wiiso_t disc, int argc, char **argv) {
    int i, type_filter = 0;
    off_t size = 0;
    const char *outname;
    char namebuf[12];

    for(i=3; i<argc; i++) {
	if(argv[i][0] != '-')
	    break;
	if(!strncmp(argv[i], "-s", 2)) {
	    char *start;
	    char *end;
	    if(argv[i][2] == '\0') {
		i++;
		if(i>=argc)
		    FAIL_CMD;
		start = argv[i];
	    } else
		start = argv[i] + 2;
	    size = strtoll(start, &end, 0);
	    if(*end)
		FAIL_CMD;
	    continue;
	}
	type_filter |= parttype_from_arg(argv[i]);
    }
    if(type_filter < 0 || i < argc-1)
	FAIL_CMD;

    size *= 1024*1024;
	  
    if(!type_filter)
	type_filter = WIISO_PART_ANY;

    if(i == argc-1)
	outname = argv[i];
    else {
	if(wiiso_get_disc_id(disc, &outname)) {
	    printf("Failed to retrieve disc id, converion aborted.\n");
	    return 1;
	}
	sprintf(namebuf, "%s.wbfs", outname);
	outname = namebuf;
    }

    printf("Saving wbfs image to %s...\n", outname);
    if(wiiso_save_wbfs(disc, outname, type_filter, size)) {
	printf("Failed to save iso file\n");
	return 1;
    }
    printf("Successfully saved wbfs image to %s\n", outname);

    return 0;
}


int main(int argc, char **argv) {
    unsigned int i;
    wiiso_t disc;

    if(argc<3 || !strcasecmp(argv[1], "--help"))
	return usage(argv[0], NULL);

    for(i=0; commands[i].command; i++) {
	if(!strcmp(argv[1], commands[i].command) && !strcmp(argv[2], "--help"))
	    return usage(argv[0], argv[1]);
	if(!strcmp(argv[2], commands[i].command))
	    break;
    }

    if(!commands[i].command)
	return usage(argv[0], NULL);

    if(!(disc = wiiso_new(WIISO_LOG_WARN))) {
	printf("wiiso_new failed\n");
	return 1;
    }

    if(wiiso_open(disc, argv[1])) {
	printf("failed to open input file %s\n", argv[1]);
	return 1;
    }

    i = commands[i].func(disc, argc, argv);
    wiiso_free(disc);
    return i;
}
