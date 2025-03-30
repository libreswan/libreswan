ipsec _kernel state
ipsec _kernel policy

# on east should see IKE_AUTH switch from distraction to any-east and
# then the IKE_SESSION_RESUME switch from resume-distraction to
# any-east.
grep -e ': switched to ' /tmp/pluto.log
