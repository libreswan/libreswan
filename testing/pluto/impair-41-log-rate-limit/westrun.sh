# ── port 4500 (esp_encapsulation_enabled) ──────────────────────────────────
# iface_udp.c: "too small packet" — packet shorter than 4 bytes (sizeof uint32_t)
printf 'ab' | nc -4 -u 192.1.2.23 4500

# iface_udp.c: "has no Non-ESP marker" — first 4 bytes non-zero, no zero marker
printf '\x01\x02\x03\x04rest' | nc -4 -u 192.1.2.23 4500

# iface_udp.c: "mangled with potential spurious non-esp marker"
# valid Non-ESP marker (4 zero bytes) followed by NON_ESP_MARKER_SIZE more zero bytes
printf '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' | nc -4 -u 192.1.2.23 4500

# iface_udp.c: "NAT-T keep-alive" — single 0xff byte with Non-ESP marker prefix
printf '\0\0\0\0\xff' | nc -4 -u 192.1.2.23 4500

# ── port 500 (plain IKE, no esp_encapsulation) ──────────────────────────────
# demux.c: "dropping packet with mangled IKE header" — under limit
printf '\0\0\0\0a' | nc -4 -u 192.1.2.23 500
# demux.c: at limit — sentinel fires here
printf '\0\0\0\0as' | nc -4 -u 192.1.2.23 500
# demux.c: over limit — suppressed to debug log
printf '\0\0\0\0asd' | nc -4 -u 192.1.2.23 500
