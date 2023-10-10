# for commands marked with '# sanitize-retransmits' remove any retransmit lines

/# sanitize-retransmits/ b match-sanitize-retransmits
b end-sanitize-retransmits

:match-sanitize-retransmits

  /retransmission; will wait/ {
      d
      /^[a-z]* #/ b end-sanitize-retransmits
      b match-sanitize-retransmits
  }
  n
  /^[a-z]* #/ b end-sanitize-retransmits

b match-sanitize-retransmits

:end-sanitize-retransmits
