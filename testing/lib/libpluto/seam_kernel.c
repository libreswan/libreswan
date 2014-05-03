void delete_ipsec_sa(struct state *st USED_BY_KLIPS,
		     bool inbound_only USED_BY_KLIPS)
{
}

bool install_inbound_ipsec_sa(struct state *st)
{
	return TRUE;
}
bool install_ipsec_sa(struct state *st, bool inbound UNUSED)
{
	return TRUE;
}

ipsec_spi_t spis[4] = { 0x12345678,
			0x34567812,
			0x56781234,
			0x78123456 };
static int spinext = 0;
ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid UNUSED,
			  int proto UNUSED, struct spd_route *sr UNUSED,
			  bool tunnel UNUSED)
{
	if (spinext == 4)
		spinext = 0;
	return htonl(spis[spinext++]);
}

const char *kernel_if_name(void);
const char *kernel_if_name()
{
	return "kernel_seam";
}

void scan_proc_shunts(void)
{
}

bool kernel_overlap_supported()
{
	return 1;
}

bool get_sa_info(struct state *st, bool inbound, monotime_t *ago)
{
	return FALSE;
}

