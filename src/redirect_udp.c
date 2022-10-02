/*    Copyright (C) 2022  Robert Caamano   */
 /*
  *   This program redirects udp packets that match specific destination prefixes & src/dst ports
  *   to either openziti edge-router tproxy port or to a locally hosted openziti service socket
  *   depending on whether there is an existing egress socket. 
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

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bcc/bcc_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>
#include <stdbool.h>

#define BPF_MAP_ID_TPROXY  1
#define BPF_MAX_ENTRIES    100
#define MAX_INDEX_ENTRIES  250

struct tproxy_tcp_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u32 tproxy_ip;
};

struct tproxy_udp_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u32 tproxy_ip;
};

struct tproxy_tuple {
    __u32 dst_ip;
	__u32 src_ip;
    __u16 index_len;
    struct tproxy_udp_port_mapping udp_mapping[65535];
    struct tproxy_tcp_port_mapping tcp_mapping[65535];
    __u16 index_table[MAX_INDEX_ENTRIES];
};

struct tproxy_key {
    __u32 dst_ip;
    __u16 prefix_len;
    __u16 pad;
};

//struct representing tproxy mapping (pinned to fs)
struct bpf_elf_map SEC("maps") zt_tproxy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .id   = BPF_MAP_ID_TPROXY,
    .size_key = sizeof(struct tproxy_key),
    .size_value =       sizeof(struct tproxy_tuple),
    .max_elem = BPF_MAX_ENTRIES,
    .pinning  = PIN_GLOBAL_NS,
};

//function for accessing tproxy map from kernel space
static inline struct tproxy_tuple *get_tproxy(struct tproxy_key dst_ip){
    struct tproxy_tuple *tu;
    tu = bpf_map_lookup_elem(&zt_tproxy_map, &dst_ip);
	return tu;
}

// Function to check if packet contains udp tuple and returns the tuple
static struct bpf_sock_tuple *get_tuple(void *data, __u64 nh_off,
                                        void *data_end, __u16 eth_proto,
                                        bool *ipv4){
    struct bpf_sock_tuple *result;
    __u8 proto = 0;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(data + nh_off);

        if ((unsigned long)(iph + 1) > (unsigned long)data_end){
            bpf_printk("header too big");
            return NULL;
		}
        if (iph->ihl != 5){
		    bpf_printk("no options allowed");
            return NULL;
		}
        proto = iph->protocol;
        *ipv4 = true;
        result = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    } else {
        return NULL;
    }

    if (((unsigned long)result + 1 > (unsigned long)data_end )|| (proto != IPPROTO_UDP)){
        return NULL;
    }
    return result;
}

//ebpf tc code
SEC("sk_udp_redirect")
int bpf_sk_assign_test(struct __sk_buff *skb){
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = (struct ethhdr *)(data);
    struct bpf_sock_tuple *tuple, sockcheck1 = {0}, sockcheck2 = {0};
    struct bpf_sock *sk; 
    int tuple_len;
    bool ipv4;
    int ret;

    if ((unsigned long)(eth + 1) > (unsigned long)data_end){
            return TC_ACT_SHOT;
	}
	//Determine if packet is part of UDP flow and get bpf_sock_tuple
    tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4);
    if (!tuple){
        return TC_ACT_OK;
	}
    tuple_len = sizeof(tuple->ipv4);
	if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
	    return TC_ACT_SHOT;
	}
	struct tproxy_tuple *tproxy;
    struct tproxy_udp_port_mapping udp_mapping;
	__u32 exponent=24;
	__u32 mask = 0xffffffff;
	__u16 maxlen = 32;
	for (__u16 count = 0;count <= maxlen; count++){
            struct tproxy_key key = {(tuple->ipv4.daddr & mask), maxlen-count,0};
            if ((tproxy = get_tproxy(key))){
                bpf_printk("prefix_len=0x%x",key.prefix_len);
                bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
                __u16 max_entries = tproxy->index_len;
                if(max_entries > MAX_INDEX_ENTRIES){
                    max_entries = MAX_INDEX_ENTRIES;
                }
                for(int index=0; index < max_entries; index++){
                    int key = tproxy->index_table[index];
                    if(tproxy->udp_mapping[key].low_port){
                        bpf_printk("udp_mapping->%d",bpf_ntohs(tproxy->udp_mapping[key].low_port));
                        //bpf_printk("udp_mapping found");
                        udp_mapping = tproxy->udp_mapping[key];
                        //bpf_printk("udp_mapping->%d",tproxy->udp_mapping[index].high_port);
                        //bpf_printk("udp_mapping->%d",tproxy->udp_mapping[index].tproxy_port);
			            return TC_ACT_OK;
                    }
                }  
            }
            if(mask == 0x00ffffff){
                exponent=16;
            }
            if(mask == 0x0000ffff){
                exponent=8;
            }
            if(mask == 0x000000ff){
                exponent=0;
            }
            if(mask == 0x00000080){
                bpf_printk("*** NO MATCH FOUND ON DEST=%x\n", bpf_ntohl(tuple->ipv4.daddr));
                return TC_ACT_OK;
            }
            if((mask >= 0x80ffffff) && (exponent >= 24)){
                mask = mask - (1 << exponent);
            }else if((mask >= 0x0080ffff) && (exponent >= 16)){
                mask = mask - (1 << exponent);
            }else if((mask >= 0x000080ff) && (exponent >= 8)){
                    mask = mask - (1 << exponent);
            }else if((mask >= 0x00000080) && (exponent >= 0)){
                mask = mask - (1 << exponent);
            }
            exponent++;
    }
    return TC_ACT_OK;
}
SEC("license") const char __license[] = "Dual BSD/GPL";
