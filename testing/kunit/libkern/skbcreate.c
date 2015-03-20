#include "kernelenv.h"
#include "skb_fake.h"

struct sk_buff *skbFromArray(const unsigned char *buf, const unsigned int len)
{
	struct sk_buff *skb;

	skb = talloc(NULL, struct sk_buff);
	memset(skb, 0, sizeof(*skb));

	skb->head = talloc_size(NULL, len + 128);
	memset(skb->head, 0x99, len + 128);     /* just so that we can tell */

	skb->data = skb->head + 64;             /* leave some head room */
	memcpy(skb->data, buf, len);
	skb->tail = skb->data + len;
	skb->end = skb->head + len + 128;

	skb->len = len;
	skb->data_len = 0;
	skb->protocol = ETH_P_IP;
	skb->mac_len = 14;
	skb->mac.raw = skb->data;

	return skb;
}

void skb_ethernet_ip_setup(struct sk_buff *skb)
{
	int iphlen;

	skb->nh.raw = skb_pull(skb, skb->mac_len);

	iphlen = (skb->nh.iph->ihl << 2);
	skb->h.raw = skb_pull(skb, iphlen);
}

