# try to suppress output specific to one init system, so that we can run with
# docker/namespaces or libvirtd/kvm without output differenves
/^Starting pluto IKE daemon for IPsec.*$/d
s/Redirecting to:.*$/Redirecting to: [initsystem]/
/^.*nsenter --mount.*$/d
