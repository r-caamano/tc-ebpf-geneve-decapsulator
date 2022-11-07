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
#include <linux/udp.h>
#include <bcc/bcc_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GENEVE_UDP_PORT         6081
#define GENEVE_VER              0
#define AWS_GNV_HDR_OPT_LEN     32 // Bytes
#define AWS_GNV_HDR_LEN         40 // Bytes

SEC("sk_skb")
int geneve(struct __sk_buff *skb) {
    __u8 proto = 0;
    int ret;
    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        return BPF_DROP;
	}
    /* get header */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
     /* ensure ip header is in packet bounds */
    if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
        return BPF_DROP;
    }
    /* get ip protocol type */
    proto = iph->protocol;
    /* check if ip protocol is UDP */
    if (proto == IPPROTO_UDP) {
        /* check outter ip header */
        struct udphdr *udph = (struct udphdr *)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
            return BPF_DROP;
        }
        /* If geneve port 6081, then do geneve header verification */
        if (bpf_ntohs(udph->dest) == GENEVE_UDP_PORT){
            //bpf_printk("GENEVE MATCH FOUND ON DPORT = %d", bpf_ntohs(udph->dest));
            //bpf_printk("UDP PAYLOAD LENGTH = %d", bpf_ntohs(udph->len));

            /* read receive geneve version and header length */
            __u8 *genhdr = (void *)(unsigned long)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
            if ((unsigned long)(genhdr + 1) > (unsigned long)skb->data_end){
                bpf_printk("geneve header is too big");
                return BPF_DROP;
            }
            int gen_ver  = genhdr[0] & 0xC0 >> 6;
            int gen_hdr_len = genhdr[0] & 0x3F;
            //bpf_printk("Received Geneve version is %d", gen_ver);
            //bpf_printk("Received Geneve header length is %d bytes", gen_hdr_len * 4);

            /* if the length is not equal to 32 bytes and version 0 */
            if ((gen_hdr_len != AWS_GNV_HDR_OPT_LEN / 4) || (gen_ver != GENEVE_VER)){
                //bpf_printk("Geneve header length:version error %d:%d", gen_hdr_len * 4, gen_ver);
                return BPF_OK;
            }

            /* Updating the skb to pop geneve header */
            //bpf_printk("SKB DATA LENGTH =%d", skb->len);
            ret = bpf_skb_adjust_room(skb, -68, BPF_ADJ_ROOM_MAC, 0);
            if (ret) {
                //bpf_printk("error calling skb adjust room.");
                return BPF_DROP;
            }
        }

    }
    return BPF_OK;
}
SEC("license") const char __license[] = "Dual BSD/GPL";