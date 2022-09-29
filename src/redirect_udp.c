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

struct tproxy_tuple {
                   __u32 dst_ip;
		   __u8  prefix_len;
		   __u32 src_ip;
		   __u32 tproxy_ip;
		   __u16 dst_port;
		   __u16 src_port;
		   __u16 tproxy_port;
           };

#define BPF_MAP_ID_TPROXY  1
#define BPF_MAX_ENTRIES    1000

//struct representing tproxy mapping (pinned to fs)
struct bpf_elf_map SEC("maps") zt_tproxy_map = {
                   .type           =       BPF_MAP_TYPE_HASH,
                   .id             =       BPF_MAP_ID_TPROXY,
                   .size_key       =       sizeof(uint32_t),
                   .size_value     =       sizeof(struct tproxy_tuple),
                   .max_elem       =       BPF_MAX_ENTRIES,
                   .pinning        =       PIN_GLOBAL_NS,
           };

//function for accessing tproxy map from kernel space
static inline struct tproxy_tuple *get_tproxy(__u32 dst_ip)
           {
                   struct tproxy_tuple *tu;

                   tu = bpf_map_lookup_elem(&zt_tproxy_map, &dst_ip);
		   return tu;
           }

// Function to check if packet contains udp tuple and returns the tuple
static struct bpf_sock_tuple *get_tuple(void *data, __u64 nh_off,
                                        void *data_end, __u16 eth_proto,
                                        bool *ipv4)
{
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
int bpf_sk_assign_test(struct __sk_buff *skb)
{
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
	//scan zt_tproxy_map to determine if there is an exact match for dest ip 
        if ((tproxy = get_tproxy(tuple->ipv4.daddr)) && (tproxy->prefix_len == 0x20)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /31 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0xfeffffff)) && (tproxy->prefix_len == 0x1f)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /30 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0xfcffffff)) && (tproxy->prefix_len == 0x1e)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /29 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0xf8ffffff)) && (tproxy->prefix_len == 0x1d)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /28 mask 
	}else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0xf0ffffff)) && (tproxy->prefix_len == 0x1c)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /27 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0xe0ffffff)) && (tproxy->prefix_len == 0x1b)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /26 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0xc0ffffff)) && (tproxy->prefix_len == 0x1a)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /25 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x80ffffff)) && (tproxy->prefix_len == 0x19)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /24 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00ffffff)) && (tproxy->prefix_len == 0x18)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	 //scan zt_tproxy_map to determine if there is an exact match on /23 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00feffff)) && (tproxy->prefix_len == 0x17)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /22 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00fcffff)) && (tproxy->prefix_len == 0x16)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /21 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00f8ffff)) && (tproxy->prefix_len == 0x15)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /20 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00f0ffff)) && (tproxy->prefix_len == 0x14)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /19 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00e0ffff)) && (tproxy->prefix_len == 0x13)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /18 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00c0ffff)) && (tproxy->prefix_len == 0x12)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /17 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0080ffff)) && (tproxy->prefix_len == 0x11)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /16 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0000ffff)) && (tproxy->prefix_len == 0x10)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	 //scan zt_tproxy_map to determine if there is an exact match on /15 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0000feff)) && (tproxy->prefix_len == 0x0f)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /14 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0000fcff)) && (tproxy->prefix_len == 0x0e)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /13 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0000f8ff)) && (tproxy->prefix_len == 0x0d)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /12 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0000f0ff)) && (tproxy->prefix_len == 0x0c)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /11 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0000e0ff)) && (tproxy->prefix_len == 0x0b)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /10 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x0000c0ff)) && (tproxy->prefix_len == 0x0a)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /9 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000080ff)) && (tproxy->prefix_len == 0x09)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /8 mask 
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000000ff)) && (tproxy->prefix_len == 0x08)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /7 mask
	}else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000000fe)) && (tproxy->prefix_len == 0x07)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /6 mask
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000000fc)) && (tproxy->prefix_len == 0x06)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /5 mask
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000000f8)) && (tproxy->prefix_len == 0x05)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        //scan zt_tproxy_map to determine if there is an exact match on /4 mask
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000000f0)) && (tproxy->prefix_len == 0x04)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /3 mask
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000000e0)) && (tproxy->prefix_len == 0x03)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /2 mask
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x000000c0)) && (tproxy->prefix_len == 0x02)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
	//scan zt_tproxy_map to determine if there is an exact match on /1 mask
        }else if ((tproxy = get_tproxy(tuple->ipv4.daddr & 0x00000080)) && (tproxy->prefix_len == 0x01)){
            bpf_printk("prefix_len=0x%x",tproxy->prefix_len);
            bpf_printk("match on dest=%x",bpf_ntohl(tproxy->dst_ip));
            bpf_printk("match on dest_port=%d",bpf_ntohs(tproxy->dst_port));
            bpf_printk("match on tproxy_ip=%x",bpf_ntohl(tproxy->tproxy_ip));
            bpf_printk("forwarding_to_tproxy_port=%d",bpf_ntohs(tproxy->tproxy_port));
        }else{
            bpf_printk("*** NO MATCH FOUND ON DEST=%x\n", bpf_ntohl(tuple->ipv4.daddr));
            return TC_ACT_OK;
        }
        //match ingress packet src/dst ports
        if ((tuple->ipv4.dport == tproxy->dst_port) && (tuple->ipv4.sport == tproxy->src_port)){
	    //tuple to look for egress socket
	    //bpf_printk("destip=%x",bpf_ntohl(tuple->ipv4.daddr));
            //bpf_printk("srcip=%x",bpf_ntohl(tuple->ipv4.saddr));
            sockcheck1.ipv4.daddr = tuple->ipv4.daddr;
            sockcheck1.ipv4.saddr = tuple->ipv4.saddr;
            //sockcheck1.ipv4.dport = bpf_htons(5060);
            sockcheck1.ipv4.dport = tproxy->dst_port;
            //sockcheck1.ipv4.sport = bpf_htons(5060);
            sockcheck1.ipv4.sport = tproxy->src_port;
            sk = bpf_sk_lookup_udp(skb, &sockcheck1, sizeof(sockcheck1.ipv4),BPF_F_CURRENT_NETNS, 0);
	    //tuple to seach for tproxy
	    /*if sk exists but does not have dst_address must be reverse ingress(intercept egress) socket
	    so we need to lookup tproxy instead after releasing*/ 
            if((sk) && (!sk->dst_ip4)){
	       bpf_sk_release(sk);
	       sockcheck2.ipv4.daddr = tproxy->tproxy_ip;
               sockcheck2.ipv4.dport = tproxy->tproxy_port;
	       sk = bpf_sk_lookup_udp(skb, &sockcheck2, sizeof(sockcheck2.ipv4),BPF_F_CURRENT_NETNS, 0);
	    }
	    //no sk found so we again need to lookup tproxy
	    if(!sk){
	       //tuple to seach for tproxy
               sockcheck2.ipv4.daddr = tproxy->tproxy_ip;
               sockcheck2.ipv4.dport = tproxy->tproxy_port;
	       sk = bpf_sk_lookup_udp(skb, &sockcheck2, sizeof(sockcheck2.ipv4),BPF_F_CURRENT_NETNS, 0);
	    }
	    if(!sk){
	       bpf_printk("No Sockets Found!");
	       return TC_ACT_SHOT;
	    }
            ret = bpf_sk_assign(skb, sk, 0);
	    bpf_sk_release(sk);
	    if(ret == 0){
	       bpf_printk("Assigned");
	       return TC_ACT_OK;
	    }else{
	       bpf_printk("failed");
	       return TC_ACT_SHOT;
	    }
        }
        return TC_ACT_OK;

}
SEC("license") const char __license[] = "Dual BSD/GPL";
