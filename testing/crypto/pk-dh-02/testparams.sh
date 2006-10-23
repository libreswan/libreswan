REF_CONSOLE_OUTPUT=../pk-dh-01/pk-dh-out.txt
REF_CONSOLE_FIXUPS=""
TESTSCRIPT=runit.sh
TEST_TYPE=unittest
TESTNAME=pk-dh-02

if [ ! -c /dev/vulcanpk ]; then
    echo This test only runs on machines with mmaped vulcan PK hardware.
    exit 99;
fi



