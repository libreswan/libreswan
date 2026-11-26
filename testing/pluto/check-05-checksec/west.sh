test -f /usr/local/libexec/ipsec/pluto && PLUTOBIN="/usr/local/libexec/ipsec/pluto"
test -f /usr/libexec/ipsec/pluto && PLUTOBIN="/usr/libexec/ipsec/pluto"

# Default CLI output is colourised with no way to disable ulgh!
# Hence, format in json.

# Zap "fortaify-able", seems to be a moving target.  "fortify" is
# compiler sensitive but changes less often.

checksec --format=json --file=${PLUTOBIN} | jq -M | sed -e '/fortify-able/ s/:.*/: .../'
