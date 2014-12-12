

before launching LSW as usual.

RJZ - LNX UDP501 # cat UDP501encap.c
/*
 * This code is GPL.
 * To compile: gcc UDP501encap.c -o UDP501encap -lipq
 *
 * Use as follows:
 *
 * modprobe ip_queue
 * UDP501encap &
 * iptables -A OUTPUT -d IPofLucentGW -j QUEUE
 * iptables -A INPUT -s IPofLucentGW -j QUEUE
 */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libipq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 2048
#define BOOL int

#define DstPort 501
	 #define DstPortHi (DstPort >> 8)
	 #define DstPortLo (DstPort & 0x00FF)
#define SrcPort 501
	 #define SrcPortHi (SrcPort >> 8)
	 #define SrcPortLo (SrcPort & 0x00FF)

typedef unsigned short u16;
typedef unsigned long u32;

u16 ip_sum_calc(u16 len_ip_header, unsigned char buff[])
{
	u16 word16;
	u32 sum = 0;
	u16 i;

	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	for (i = 0; i < len_ip_header; i = i + 2) {
		word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
		sum = sum + (u32) word16;
	}

	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement the result
	sum = ~sum;

	return (u16) sum;
}

static void die(struct ipq_handle *h)
{
	ipq_perror("passer");
	ipq_destroy_handle(h);
	exit(1);
}

int main(int argc, char **argv)
{
	int status;
	unsigned char buf[BUFSIZE];
	struct ipq_handle *h;
	unsigned char *newPayload;
	u16 srcaddr[4], dstaddr[4];
	u16 newCS;
	int ip_header_len;
	u16 udp_len;
	int i;

	h = ipq_create_handle(0, PF_INET);
	if (!h)
		die(h);

	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0)
		die(h);

	do {
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status < 0)
			die(h);

		switch (ipq_message_type(buf)) {
		case NLMSG_ERROR:
			fprintf(stderr, "Received error message %d\n",
				ipq_get_msgerr(buf));
			break;

		case IPQM_PACKET:
		{
			ipq_packet_msg_t *m = ipq_get_packet(buf);
			//Enable this to debug the incoming/outgoing packets:
			//printf("0x%02x %s -> %s (%d)\n",  m->payload[9], m->indev_name, m->outdev_name, m->data_len);

			if (m->outdev_name[0] == 0x0) {
				// INPUT
				ip_header_len = (m->payload[0] & 0xF) * 4;
				u16 new_ip_len = m->data_len - ip_header_len -
						 8;
				newPayload = malloc(new_ip_len);
				memcpy(newPayload,
				       m->payload + ip_header_len + 8,
				       new_ip_len);
				status = ipq_set_verdict(h, m->packet_id,
							 NF_ACCEPT, new_ip_len,
							 newPayload);
				free(newPayload);
			} else {
				u16 ip_len =
					(m->payload[2] << 8 & 0xff00) +
					(m->payload[3] & 0xff);
				ip_header_len = (m->payload[0] & 0xF) * 4;
				u16 new_ip_len = ip_len + ip_header_len + 8;
				newPayload = malloc(new_ip_len);
				// Copy prev packet
				char *dst = newPayload;
				char *org = m->payload;
				// Copy IP header
				memcpy(dst, org, ip_header_len);
				dst += ip_header_len;
				// Update IP length field
				newPayload[2] = new_ip_len >> 8;
				newPayload[3] = new_ip_len & 0x00ff;
				// Set IP protocol field to UDP
				newPayload[9] = 0x11;
				// Calculate and update IP cksum
				newPayload[10] = newPayload[11] = 0x00;
				newCS = ip_sum_calc(ip_header_len, newPayload);
				newPayload[10] = newCS >> 8;
				newPayload[11] = newCS & 0x00FF;
				// Create UDP header
				dst[0] = SrcPortHi;             // src port
				dst[1] = SrcPortLo;             // src port
				dst[2] = DstPortHi;             // dst port
				dst[3] = DstPortLo;             // dst port
				u16 new_udp_len = new_ip_len - ip_header_len;
				dst[4] = new_udp_len >> 8;      // total len
				dst[5] = new_udp_len & 0x00ff;  // total len
				dst[6] = 0x00;                  // Cksum
				dst[7] = 0x00;                  // Cksum
				dst += 8;
				// Clone the rest of the packet
				memcpy(dst, org, ip_len);
				status = ipq_set_verdict(h, m->packet_id,
							 NF_ACCEPT, new_ip_len,
							 newPayload);
				free(newPayload);
			}
			if (status < 0)
				die(h);
			break;
		}

		default:
			fprintf(stderr, "Unknown message type!\n");
			break;
		}
	} while (1);

	ipq_destroy_handle(h);
	return 0;
}

/*
   >> I discussed this subject here:
   >>
   > http://lists.openswan.org/pipermail/users/2008-February/014030.html
   > based on
   >> what I could capture under Windows, the relevant part
   > of it is:
   >> "I'm trying to connect OpenSwan to a Lucent
   > VPN Gateway, which according to
   >> its ASCII interpretation of its Vendor ID payload is:
   >>
   > 4C5647392E312E3235353A425249434B3A392E312E323535="LVG9.1.255:BRICK:9.1.255".
   > I
   >> can connect to it by means of the Lucent VPN Client
   > V7.1.2 on a Windows XP
   >> computer (Vendor ID=
   > 4C5643372E312E323A5850="LVC7.1.2:XP")."
   >
   > Thanks. Normally vendorids are md5sum's of some text,
   > though in this case
   > that does not seem to be the case. I added them as-is to
   > vendor.c for now.
   >
   >> Seems one can know the running version of the client
   > and server just looking
   >> on the vendor id part of an ASCII capture dump.
   >> Interesting thing is, as explained to you privatelly,
   > the way the PSK gets
   >> handled here. Under the LVC (windows) I had to
   > configure a PSK like:
   >> <MyCompanysPSK> where the real PSK is 9 ASCII
   > characters long. However, I
   >> could find that in order to have LSW establishing
   > phase 1 succesfully I had to
   >> add the string "01234567890" as a trailer,
   > i.e. my ipsec.secrets looks like:
   >> !@#$% <MyCompanysGWipAddress> : PSK
   > "<MyCompanysPSK>01234567890"
   >>
   >> what gives a PSK of lenght 20. Not sure on how they
   > handle it but my guess is
   >> they just take the PSK the user configures, add the
   > string
   >> "01234567890123456789" and take the first 20
   > bytes of it. Easy way to hook you
   >> on their client while still keeping it simply to
   > develop.
   >>
   >> And I'm not sure if the user !@#$% is the one the
   > GW admin configured on it or
   >> if it's the way they handle it but whatever else I
   > configure, the GW just
   >> don't respond anything back to me.
   >
   > Thanks! I put a note of this in docs/lucent-client.txt, and
   > it will end up
   > in the new wiki once we have it online.
   >
   >>> Looks like a resend, you can ignore it.
   >> Strangely, I *always* do receive the duplicate packet
   > warning. Another
   >> interesting thing is Lucent's VPN client
   > doesn't exchange any CFG at all...
   >> I'm wondering now if I need it indeed. The server
   > sends it to me but seems
   >> like LSW only configures the local IP address based on
   > it. I supossed it was
   >> going to be able to configure something else, such as
   > DNS or things like that.
   >
   > Libreswan does support DNS/WINS via XAUTH/ModeConfig. Though
   > as a client, we
   > might be ignoring it, since we have no structured way of
   > modifying resolv.conf
   > in any modern way (eg dbus/networkmanager). I believe we
   > might only pass it
   > as env variables to the updown script.
   >
   >> The LVC do more things with no CFG at all, configures
   > the DNS and WINS servers
   >> for instance, something I'll need to do manually
   > via a script (or can it be
   >> made automatically somehow by LSW?)
   >
   > You can copy the stock _updown script and add resolv.conf
   > rewriting to it,
   > and configure the new script using leftupdown=
   >
   >>>> and this one from pluto's debug:
   >>>>  3) "Intranet" #1: XAUTH:
   > Unsupported attribute: INTERNAL_ADDRESS_EXPIRY
   >>> You can also ignore this. Libreswan does not
   > support INTERNAL_ADDRESS_EXPIRY,
   >>> so it wont drop the IP address or ask for a new
   > one.
   >> Same for "ignoring informational payload, type
   > IPSEC_RESPONDER_LIFETIME"
   >> above?
   >
   > Yes. the remote is telling us how long they will keep the
   > SA around. Libreswan
   > does not really care what the remote does. If the remote
   > wants to rekey, it
   > will and can do it anytime. We do enforce our own SA life
   > similarly.
   >
   > Paul
 */

