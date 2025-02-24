# for commands marked with '# sanitize-retransmits' remove any retransmit lines

/# sanitize-retransmits/ b sanitize-retransmits
b end-sanitize-retransmits

# normal
:sanitize-retransmits
  # print and read next line
  n
  /^[a-z]* #/ b end-sanitize-retransmits

:match-sanitize-retransmits
  /retransmission; will wait/ b next-sanitize-retransmits
  /discarding packet received during/ b next-sanitize-retransmits
  b sanitize-retransmits

# drop current line (append next, delete current line)
:next-sanitize-retransmits
  N
  s/^.*\n//
  /^[a-z]* #/ b end-sanitize-retransmits
  b match-sanitize-retransmits

:end-sanitize-retransmits
