# do not install strongswan debian package
# It conflict with libreswan and would overwrite "/usr/sbin/ipsec" from libreswan

TESTING_DEB_PACKAGES ?= \
	bind9utils \
	python3-pexpect \
	python3-openssl \
	python3-distutils
