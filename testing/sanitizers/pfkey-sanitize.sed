s/pid=\([0-9]*\) /pid=987 /g
s/(pid=\([0-9]*\))/(pid=987)/g
s/\(.*pfkey_lifetime_parse: .*\) add=.* \(.*\)/\1 \2/
s/\(.*pfkey_lifetime_parse: .*\) use=.* \(.*\)/\1 \2/

