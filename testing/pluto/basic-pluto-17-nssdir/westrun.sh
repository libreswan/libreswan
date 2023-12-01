IPSEC_DIR=/etc/ipsec.d/
IPSEC_TEST_DIR=/tmp/TESTipsec.d
mkdir ${IPSEC_TEST_DIR}
rm -f ${IPSEC_DIR}/*.db
ipsec initnss --nssdir ${IPSEC_TEST_DIR}
find ${IPSEC_DIR}      -name '*.db' | sort  # should show no db files
find ${IPSEC_TEST_DIR} -name '*.db' | sort  # should show db files
ipsec checknss --nssdir ${IPSEC_TEST_DIR}
find ${IPSEC_DIR}      -name '*.db' | sort  # should show no db files
find ${IPSEC_TEST_DIR} -name '*.db' | sort  # should show db files
ipsec newhostkey --nssdir ${IPSEC_TEST_DIR}
rm -rf ${IPSEC_TEST_DIR}
