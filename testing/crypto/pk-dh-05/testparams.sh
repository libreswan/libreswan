REF_CONSOLE_OUTPUT=pk-dh-out.txt
REF_CONSOLE_FIXUPS=""
TESTSCRIPT=runit.sh
TEST_TYPE=unittest
TESTNAME=pk-dh-05

if [ ! -c /dev/vulcanpk ]; then
    echo This test only runs on machines with mmaped vulcan PK hardware.
    exit 99;
fi



