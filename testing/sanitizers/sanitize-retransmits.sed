# for commands marked with '# sanitize-retransmits' remove any retransmit lines

/# sanitize-retransmits/ b match
b end

:match

  /retransmission; will wait/ {
      d
      /^[a-z]* #/ b end
      b match
  }
  n
  /^[a-z]* #/ b end
  b match

:end
