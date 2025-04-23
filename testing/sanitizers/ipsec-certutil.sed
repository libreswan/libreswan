# match: ipsec certutil and certutil

/^ [a-z ]*certutil /,/^[a-z][a-z]* #$/ {

  # strip out any raw keys
:ipsec-certutil-strip
  /^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ {
    N
    s/.*\n//
    b ipsec-certutil-strip
  }

  s/Serial Number: .*/Serial Number: SERIAL/
  s/Not Before: .*/Not Before: TIMESTAMP/
  s/Not After : .*/Not After : TIMESTAMP/

}
