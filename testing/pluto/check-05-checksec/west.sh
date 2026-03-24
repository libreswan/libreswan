test -f /usr/local/libexec/ipsec/pluto && PLUTOBIN="/usr/local/libexec/ipsec/pluto"
test -f /usr/libexec/ipsec/pluto && PLUTOBIN="/usr/libexec/ipsec/pluto"
# default CLI output is colourised with no way to disable
# ulgh!
checksec --format=json --file=${PLUTOBIN} | jq -M
