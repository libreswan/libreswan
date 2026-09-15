# for commands marked with '# sanitize-retransmits' remove any retransmit lines

/ # sanitize-retransmits/ b sanitize-retransmits
b end-sanitize-retransmits

# normal
:sanitize-retransmits
  # print and read next line
  n
  /^[a-z]* #/ b end-sanitize-retransmits

:match-sanitize-retransmits
  # IKEv1
  /: discarding packet received during /	b next-sanitize-retransmits
  # IKEv2
  /: retransmitting [A-Z_a-z ]* request;/	b next-sanitize-retransmits
  /: retransmitting CREATE_CHILD_SA rekey ike;/	b next-sanitize-retransmits
  # ???
  / retransmission; will wait/			b next-sanitize-retransmits
  / dropping [A-Z_]* response with duplicate /  b next-sanitize-retransmits
  / dropping [A-Z_]* response with in-progress /  b next-sanitize-retransmits
  / retransmitting delete /   	   	       b next-sanitize-retransmits
  b sanitize-retransmits

# drop current line (append next, delete current line)
:next-sanitize-retransmits
  N
  s/^.*\n//
  /^[a-z]* #/ b end-sanitize-retransmits
  b match-sanitize-retransmits

:end-sanitize-retransmits
