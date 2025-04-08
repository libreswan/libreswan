# playing with end cert Basic Constraint should have no effect, these
# all establish

./bc.sh west-bc-ca-missing
./bc.sh west-bc-ca         n
./bc.sh west-bc-ca         n critical
./bc.sh west-bc-ca         y
./bc.sh west-bc-ca         y critical
