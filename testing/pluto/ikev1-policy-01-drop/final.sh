hostname | grep east > /dev/null && grep "ignoring IKEv1 packet" /tmp/pluto.log
hostname | grep east > /dev/null && (grep "sending notification INVALID_MAJOR_VERSION" /tmp/pluto.log >/dev/null && echo "A reply SHOULD NOT have been sent")
