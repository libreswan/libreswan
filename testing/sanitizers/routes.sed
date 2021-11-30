s/ proto stati.*$//
s/ proto static onlin.*$//
# f32->f35
s/bytes  packets  errors  dropped overrun mcast/bytes  packets  errors  dropped missed  mcast/
s/output-mark \(0x[0-9a-zA-Z]*\).*/output-mark \1/
