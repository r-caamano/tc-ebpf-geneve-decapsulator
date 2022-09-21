#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bcc/bcc_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


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

        if ((unsigned long)(eth + 1) > (unsigned long)data_end)
                return TC_ACT_SHOT;
	//Determin if packet is part of UDP flow and get bpf_sock_tuple
        tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4);
        if (!tuple)
                return TC_ACT_OK;
        tuple_len = sizeof(tuple->ipv4);
	if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end)
		return TC_ACT_SHOT;
        //match ingress packet dest ip/destport
        if (tuple->ipv4.dport == bpf_htons(5060) && (tuple->ipv4.sport == bpf_htons(5060))){
	    //tuple to look for egress socket
            sockcheck1.ipv4.daddr = tuple->ipv4.daddr;
            sockcheck1.ipv4.saddr = tuple->ipv4.saddr ;
            sockcheck1.ipv4.dport = bpf_htons(5060);
            sockcheck1.ipv4.sport = bpf_htons(5060);
            sk = bpf_sk_lookup_udp(skb, &sockcheck1, sizeof(sockcheck1.ipv4),BPF_F_CURRENT_NETNS, 0);
	    //tuple to seach for tproxy
            sockcheck2.ipv4.daddr = bpf_htonl(0x7f000001);
            sockcheck2.ipv4.dport = bpf_htons(39150);
	    /*if sk exists but does not have dst_address must be reverse ingress(intercept egress) socket
	    so we need to lookup tproxy instead after releasing*/ 
            if((sk) && (!sk->dst_ip4)){
	       bpf_sk_release(sk);
	       sk = bpf_sk_lookup_udp(skb, &sockcheck2, sizeof(sockcheck2.ipv4),BPF_F_CURRENT_NETNS, 0);
	    }
	    //no sk found so we again need to lookup tproxy
	    if(!sk){
	       sk = bpf_sk_lookup_udp(skb, &sockcheck2, sizeof(sockcheck2.ipv4),BPF_F_CURRENT_NETNS, 0);
	    }
	    if(!sk){
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
