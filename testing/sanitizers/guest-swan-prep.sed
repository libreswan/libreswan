# match: .../swan-prep

/^\/.*\/swan-prep/ b match
b end

:match

  # print and read next line
  n
  /^[a-z]* #/ b end

  # f28 gets different NSS errors compared to f22
  s/: SEC_ERROR_UNRECOGNIZED_OID: Unrecognized Object Identifier./: SEC_ERROR_.../
  s/: SEC_ERROR_INVALID_ARGS: security library: invalid arguments./: SEC_ERROR_.../

b match

:end
