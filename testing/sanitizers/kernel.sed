# Note: kernel messages aren't just at the start of the line.  Instead
# they get concatenated to what ever is there, and that needs to be
# preserved.  Hence a join is used.

:start-kernel

  # [ 111.628924] -> [00.00]
  s/\[\s*[0-9]\+\.[0-9]\+\] /[ 00.00] /

  # Only zap select kernel error messages.  Unexpected messages or
  # messages involving aliens are not zapped.  Use [00.00] to anchor
  # the message string and not ^, the message can appear in the middle
  # of other output.

  /\[ 00.00] AVX or AES-NI instructions are not detected/ b zap-kernel
  /\[ 00.00] IPv4 over IPsec tunneling driver/ b zap-kernel
  /\[ 00.00] IPsec XFRM device driver/ b zap-kernel
  /\[ 00.00] alg: No test for / b zap-kernel
  /\[ 00.00] tun: Universal TUN\/TAP device driver/ b zap-kernel
  /\[ 00.00] SELinux: / b zap-kernel
  /\[ 00.00] gre: GRE over IPv4 demultiplexor driver/ b zap-kernel
  /\[ 00.00] ip_gre: GRE over IPv4 tunneling driver/ b zap-kernel
  /\[ 00.00] PPP / b zap-kernel
  /\[ 00.00] NET: / b zap-kernel
  /\[ 00.00] hrtimer: interrupt took / b zap-kernel
  /\[ 00.00] kauditd_printk_skb: / b zap-kernel
  /\[ 00.00] audit: / b zap-kernel
  /\[ 00.00] Bluetooth: / b zap-kernel # yes, apparently NIC has Bluetooth
  /\[ 00.00] .*: performance on this CPU would be suboptimal/ b zap-kernel
  /\[ 00.00] .* used greatest stack depth: [0-9]* bytes left/ b zap-kernel
  /\[ 00.00] clocksource: Long readout interval, skipping watchdog check/ b zap-kernel

b end-kernel

:zap-kernel

  # Need to undo any damage caused by the message being injected into
  # the middle of other output. For instance:
  #
  #   This is a line
  #
  # becomes:
  #
  #   This is a [00.00] KERNEL MESSAGE
  #   line

  # Do this by joining the two lines and then zapping the message

  # Form: This a [ 00.00] KERNEL MESSAGE\nline
  N
  # Zap: [ 00.00 KERNEL MESSAGE\n
  s/\[ 00.00] [^\n]*\n//

  # Was the next line also a kernel message.

b start-kernel

:end-kernel
