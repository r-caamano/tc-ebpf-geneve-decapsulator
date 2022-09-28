/*    Copyright (C) 2022  Robert Caamano   */
 /*
  *
  *   This program inserts a rule into an existing pinned 
  *   zt_tproxy_map hash table created by the redirect_udp
  *   program when attatched to an interface via tc
  *
  *   This program is free software: you can redistribute it and/or modify
  *   it under the terms of the GNU General Public License as published by
  *   the Free Software Foundation, either version 3 of the License, or
  *   (at your option) any later version.

  *   This program is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *   GNU General Public License for more details.
  *   see <https://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syscall.h"
#include <arpa/inet.h>

struct tproxy_tuple {
                   __u32 dst_ip;
                   __u32 src_ip;
		   __u32 tproxy_ip;
                   __u16 dst_port;
                   __u16 src_port;
		   __u16 tproxy_port;
           };

int main(int argc, char **argv){
    union bpf_attr map;
    const char *path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
    char *endPtr;
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <hex_dest_prefix ex. 0a000001> <dst_port> <src_port> <tproxy_port>\n", argv[0]);
        exit(0);
    }
    int32_t key = htonl(strtol(argv[1],&endPtr,16));
    struct tproxy_tuple rule = {
	key,//dest address also used as key
	0x0,//zero source address
        0x0100007f,//standard tproxy localhost 
        htons((unsigned short)strtol(argv[2],&endPtr,10)),//dst_port
        htons((unsigned short)strtol(argv[3],&endPtr,10)),//dst_port
        htons(atoi(argv[4]))//tproxy_port
    };
    //Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t) path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = bpf(BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1){
	printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    //insert tproxy socket rule into map
    map.map_fd = fd;
    map.key = (uint64_t) &key;
    map.value = (uint64_t) &rule;
    map.flags = BPF_ANY;
    int result = bpf(BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result){
	printf("MAP_DELETE_ELEM: %s \n", strerror(errno));
        exit(1);
    }
    close(fd);
}
