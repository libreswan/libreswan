# match: .../swan-prep

/^\/.*\/swan-prep/ b next-swan-prep

b end-swan-prep

:drop-swan-prep
  # read next line (drop current)
  N
  s/^.*\n//
  b match-swan-prep

:next-swan-prep
  # advance to next line (print current, read next)
  n

:match-swan-prep
  # next command?
  /^[a-z][a-z]*#/ b end-swan-prep
  /^[a-z][a-z]* #/ b end-swan-prep

  # f28 gets different NSS errors compared to f22
  s/: SEC_ERROR_UNRECOGNIZED_OID: Unrecognized Object Identifier./: SEC_ERROR_.../
  s/: SEC_ERROR_INVALID_ARGS: security library: invalid arguments./: SEC_ERROR_.../

b next-swan-prep

:end-swan-prep
