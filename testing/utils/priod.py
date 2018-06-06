#!/usr/bin/env python3

# break down a decimal representation of an SA priority into its fields
# synopsis: priod.py prio...
# Copyright (C) 2018 D. Hugh Redelmeier (hugh@mimosa.com)


# from calculate_sa_prio(): uint32_t prio = pmax - (portsw << 17 | protow << 16 | srcw << 8 | dstw);

import sys

for p in sys.argv[1:]:
	n = int(p)
	pmin = (n >> 19) << 19
	pmax = pmin + (1 << 19) - 1
	pname = ['manual', 'static', 'oppo', 'oppo_anon'][pmin >> 19]
	if pmin == 0:
		print('{} {} {}'.format(n, hex(n), pname))
	else:
		# n == pmax - fields
		fields = pmax - n
		portsw = fields >> 17
		protow = (fields >> 16) & 1
		srcw = (fields >> 8) & 255
		dstw = fields & 255
		# print(n, ' ', hex(n), ' ', pname, ' portsw ', portsw, ', protow ', protow, ', srcw ', srcw, ', dstw ', dstw, sep='')
		print('{} {} {} portsw {}, protow {}, srcw {}, dstw {}'.format(n, hex(n), pname, portsw, protow, srcw, dstw))
