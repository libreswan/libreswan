# confirm the correct ID type was received by EAST; unfortunately
# IKEv1 doesn't log the ID type being sent.
grep '^[^|].*USER_FQDN' /tmp/pluto.log
