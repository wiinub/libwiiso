#ifndef _SECRET_H
#define _SECRET_H

#define ROOT_CA_MOD "\
\xf8\x24\x6c\x58\xba\xe7\x50\x03\x01\xfb\xb7\xc2\xeb\xe0\x01\x05\
\x71\xda\x92\x23\x78\xf0\x51\x4e\xc0\x03\x1d\xd0\xd2\x1e\xd3\xd0\
\x7e\xfc\x85\x20\x69\xb5\xde\x9b\xb9\x51\xa8\xbc\x90\xa2\x44\x92\
\x6d\x37\x92\x95\xae\x94\x36\xaa\xa6\xa3\x02\x51\x0c\x7b\x1d\xed\
\xd5\xfb\x20\x86\x9d\x7f\x30\x16\xf6\xbe\x65\xd3\x83\xa1\x6d\xb3\
\x32\x1b\x95\x35\x18\x90\xb1\x70\x02\x93\x7e\xe1\x93\xf5\x7e\x99\
\xa2\x47\x4e\x9d\x38\x24\xc7\xae\xe3\x85\x41\xf5\x67\xe7\x51\x8c\
\x7a\x0e\x38\xe7\xeb\xaf\x41\x19\x1b\xcf\xf1\x7b\x42\xa6\xb4\xed\
\xe6\xce\x8d\xe7\x31\x8f\x7f\x52\x04\xb3\x99\x0e\x22\x67\x45\xaf\
\xd4\x85\xb2\x44\x93\x00\x8b\x08\xc7\xf6\xb7\xe5\x6b\x02\xb3\xe8\
\xfe\x0c\x9d\x85\x9c\xb8\xb6\x82\x23\xb8\xab\x27\xee\x5f\x65\x38\
\x07\x8b\x2d\xb9\x1e\x2a\x15\x3e\x85\x81\x80\x72\xa2\x3b\x6d\xd9\
\x32\x81\x05\x4f\x6f\xb0\xf6\xf5\xad\x28\x3e\xca\x0b\x7a\xf3\x54\
\x55\xe0\x3d\xa7\xb6\x83\x26\xf3\xec\x83\x4a\xf3\x14\x04\x8a\xc6\
\xdf\x20\xd2\x85\x08\x67\x3c\xab\x62\xa2\xc7\xbc\x13\x1a\x53\x3e\
\x0b\x66\x80\x6b\x1c\x30\x66\x4b\x37\x23\x31\xbd\xc4\xb0\xca\xd8\
\xd1\x1e\xe7\xbb\xd9\x28\x55\x48\xaa\xec\x1f\x66\xe8\x21\xb3\xc8\
\xa0\x47\x69\x00\xc5\xe6\x88\xe8\x0c\xce\x3c\x61\xd6\x9c\xbb\xa1\
\x37\xc6\x60\x4f\x7a\x72\xdd\x8c\x7b\x3e\x3d\x51\x29\x0d\xaa\x6a\
\x59\x7b\x08\x1f\x9d\x36\x33\xa3\x46\x7a\x35\x61\x09\xac\xa7\xdd\
\x7d\x2e\x2f\xb2\xc1\xae\xb8\xe2\x0f\x48\x92\xd8\xb9\xf8\xb4\x6f\
\x4e\x3c\x11\xf4\xf4\x7d\x8b\x75\x7d\xfe\xfe\xa3\x89\x9c\x33\x59\
\x5c\x5e\xfd\xeb\xcb\xab\xe8\x41\x3e\x3a\x9a\x80\x3c\x69\x35\x6e\
\xb2\xb2\xad\x5c\xc4\xc8\x58\x45\x5e\xf5\xf7\xb3\x06\x44\xb4\x7c\
\x64\x06\x8c\xdf\x80\x9f\x76\x02\x5a\x2d\xb4\x46\xe0\x3d\x7c\xf6\
\x2f\x34\xe7\x02\x45\x7b\x02\xa4\xcf\x5d\x9d\xd5\x3c\xa5\x3a\x7c\
\xa6\x29\x78\x8c\x67\xca\x08\xbf\xec\xca\x43\xa9\x57\xad\x16\xc9\
\x4e\x1c\xd8\x75\xca\x10\x7d\xce\x7e\x01\x18\xf0\xdf\x6b\xfe\xe5\
\x1d\xdb\xd9\x91\xc2\x6e\x60\xcd\x48\x58\xaa\x59\x2c\x82\x00\x75\
\xf2\x9f\x52\x6c\x91\x7c\x6f\xe5\x40\x3e\xa7\xd4\xa5\x0c\xec\x3b\
\x73\x84\xde\x88\x6e\x82\xd2\xeb\x4d\x4e\x42\xb5\xf2\xb1\x49\xa8\
\x1e\xa7\xce\x71\x44\xdc\x29\x94\xcf\xc4\x4e\x1f\x91\xcb\xd4\x95"

#define ROOT_CA_EXP "\x00\x01\x00\x01"

static const uint8_t common_key[] = { 0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7 };
static const uint8_t korean_key[] = { 0x63, 0xb8, 0x2b, 0xb4, 0xf4, 0x61, 0x4e, 0x2e, 0x13, 0xf2, 0xfe, 0xfb, 0xba, 0x4c, 0x9b, 0x7e };

#endif
