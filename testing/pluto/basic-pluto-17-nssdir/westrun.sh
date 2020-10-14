IPSEC_DIR=/etc/ipsec.d/
IPSEC_TEST_DIR=/tmp/TESTipsec.d
mkdir ${IPSEC_TEST_DIR}
rm -f ${IPSEC_DIR}/*.db
ipsec initnss --nssdir ${IPSEC_TEST_DIR}
ls ${IPSEC_DIR} | egrep '*.db' # should show no db files
ls ${IPSEC_TEST_DIR} | egrep '*.db' # should show db files
ipsec checknss --nssdir ${IPSEC_TEST_DIR}
ls ${IPSEC_DIR} | egrep '*.db' # should show no db files
ls ${IPSEC_TEST_DIR} | egrep '*.db' # should show db files
ipsec newhostkey --nssdir ${IPSEC_TEST_DIR} > /dev/null 2> /dev/null
rm -rf ${IPSEC_TEST_DIR}
