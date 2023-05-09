
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "bpf_helpers.h"
#include "bpf.h"


// AF_XDP Socket Map
struct  bpf_map_def SEC("maps") xsks_map = {
  .type = BPF_MAP_TYPE_XSKMAP,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 128,
};


// Queue Index config Map
struct  bpf_map_def SEC("maps") qid_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 128,
};


// XDP program //
SEC("xdp_sock") int xdp_tamper(struct xdp_md *ctx) 
{
  int *qidconf, index = ctx->rx_queue_index;
  qidconf = bpf_map_lookup_elem(&qid_map, &index);
  if(!qidconf){
    return XDP_ABORTED;
  }

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth;
  struct iphdr *ip;
  struct ipv6hdr *ipv6;

  if(data < data_end){
    __u64 packet_size = data_end - data;

    // L2
    eth = data;
    if (data + sizeof(*eth) > data_end) {
      return XDP_ABORTED;
    }

    // L3
    switch(__constant_htons(eth->h_proto)){
      case ETH_P_IP:
        ip = data + sizeof(*eth);
        if(data + sizeof(*ip) > data_end) {
          return XDP_ABORTED;
        }
        return bpf_redirect_map(&xsks_map, index, XDP_DROP);
        break;
      case ETH_P_IPV6:
        ipv6 = data + sizeof(*eth);
        if(data + sizeof(*ipv6) > data_end) {
          return XDP_ABORTED;
        }
        return bpf_redirect_map(&xsks_map, index, XDP_DROP);
        break;
      default:
        break;
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
