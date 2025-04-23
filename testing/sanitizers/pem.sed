# remove the random content of PEM output

/^-----BEGIN /,/^-----END / {

  /^[^-].*/ d

}
