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
#include <arpa/inet.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

struct tproxy_tuple {
    __u32 dst_ip;
    __u32 src_ip;
	__u32 tproxy_ip;
    __u16 dst_port;
    __u16 src_port;
	__u16 tproxy_port;
};

struct tproxy_key {
           __u32  dst_ip;
		   __u16  prefix_len;
           __u16  pad;
};

int32_t ip2l(char *ip){
    char *endPtr;
    int32_t byte1 = strtol(ip,&endPtr,10);
    if((byte1 <= 0) || (byte1 > 223) || (!isdigit(*(endPtr + 1)))){
        printf("Invalid IP Address: %s\n",ip);
        exit(1);	
    }
    int32_t byte2 = strtol(endPtr + 1,&endPtr,10);
    if((byte2 < 0) || (byte2 > 255) || (!isdigit(*(endPtr + 1)))){
       printf("Invalid IP Address: %s\n",ip);
       exit(1);
    }
    int32_t byte3 = strtol(endPtr + 1,&endPtr,10);
    if((byte3 < 0) || (byte3 > 255) || (!isdigit(*(endPtr + 1)))){
       printf("Invalid IP Address: %s\n",ip);
       exit(1);
    }
    int32_t byte4 = strtol(endPtr + 1,&endPtr,10);
    if((byte4 < 0) || (byte4 > 255) || (!(*(endPtr) == '\0'))){
       printf("Invalid IP Address: %s\n",ip);
       exit(1);
    }
    return (byte1 << 24) + (byte2 << 16) + (byte3 << 8) + byte4;
}

unsigned short port2s(char *port){
    char *endPtr;
    int32_t tmpint = strtol(port,&endPtr,10);
    if((tmpint <=0) || (tmpint > 65535) || (!(*(endPtr) == '\0'))){
       printf("Invalid Port: %s\n", port);
       exit(1);
    }
    unsigned short usint = (unsigned)tmpint;
    return usint;
}

__u16 len2u16(char *len){
    char *endPtr;
    int32_t tmpint = strtol(len,&endPtr,10);
    if((tmpint <= 0) || (tmpint > 32) || (!(*(endPtr) == '\0'))){
       printf("Invalid Prefix Length: %s\n", len);
       exit(1);
    }
    __u16 u16int = (__u16)tmpint;
    return u16int;
}

int main(int argc, char **argv){
    union bpf_attr map;
    const char *path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <ip dest address or prefix> <prefix length> <dst_port> <src_port> <tproxy_port>\n", argv[0]);
        exit(0);
    }
    struct tproxy_key key = {htonl(ip2l(argv[1])), len2u16(argv[2]),0};
    struct tproxy_tuple rule = {
	    htonl(ip2l(argv[1])),
	    0x0,//zero source address
        0x0100007f,//standard tproxy localhost 
        htons(port2s(argv[3])),//dst_port
        htons(port2s(argv[4])),//src_port
        htons(port2s(argv[5]))//tproxy_port
    };
    //Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t) path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1){
	printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    //insert tproxy socket rule into map
    map.map_fd = fd;
    map.key = (uint64_t) &key;
    map.value = (uint64_t) &rule;
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result){
	printf("MAP_DELETE_ELEM: %s \n", strerror(errno));
        exit(1);
    }
    close(fd);
}
