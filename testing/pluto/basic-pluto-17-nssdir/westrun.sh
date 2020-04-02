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
ipsec newhostkey --nssdir ${IPSEC_TEST_DIR} --output ${IPSEC_TEST_DIR}/test.secrets > /dev/null 2> /dev/null
# should show F4 (0x010001) is used for new keys
grep "PublicExponent: 0x010001" ${IPSEC_TEST_DIR}/test.secrets
rm -rf ${IPSEC_TEST_DIR}
