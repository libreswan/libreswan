# sanitize: ip route list

/^ ip route list/,/^[a-z]* #/ {

    # some versions embed spaces in the middle or end of the output
    s/  / /g
    s/ $//

}
