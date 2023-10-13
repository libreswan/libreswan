# as in: grep -E -i "IKE|ipsec-" /var/log/audit/audit.log

/audit.log$/ b match-linux-audit
/^ ausearch -r -m seccomp -ts boot/ b match-linux-audit

b end-linux-audit

:match-linux-audit

  # print and read next line
  n
  /^[a-z]* #/ b end-linux-audit

:next-linux-audit

  s/audit([^ ]*)/audit(XXX)/
  s/pid=[0-9]* /pid=PID /
  s/auid=[0-9]* /auid=AUID /
  s/ses=[0-9]* /ses=SES /
  s/old=[0-9]* /old=XXX /
  s/spi=[0-9]*(0x[0-9a-f]*) /spi=DEC(HEX) /g
  s/ipcomp=[0-9]*(0x[0-9a-f]*) /spi=DEC(HEX) /g
  s/ip=0x([0-9a-f]*) /ip=(XXX) /g
  /^[ 00.00] audit.*$/d
  # selinux differs for /usr/local and rpm install.
  # this fakes the rpm selinux policy back to our /usr/local selinux policy
  s/ipsec_t/unconfined_service_t/g
  # some versions mistakenly used a double space, dont fail over those
  s/  / /g
  # some times we get extra: UID="root" AUID="unset"
  /^UID="root" AUID="unset"$/d
  # rhel and upstream diff in printed auth algo 0
  s/auth=0/auth=OAKLEY__0/g
  # and embedded group separators
  s/ res=\([a-z]*\)'\o035/ res=\1'^]/
  /^.* kauditd_printk_skb: .*$/d

b match-linux-audit

:end-linux-audit
