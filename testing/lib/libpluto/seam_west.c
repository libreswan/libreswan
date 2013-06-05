struct iface_dev ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port if1 = {
	.ip_dev = &ifd1,
	.port   = 500,
	//.ip_addr = htonl(0xc0010217),
	.ip_addr.u.v4.sin_family = AF_INET,
	.ip_addr.u.v4.sin_addr.s_addr = 0x2d0201c0,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 1,
	.change    = IFN_KEEP
};

