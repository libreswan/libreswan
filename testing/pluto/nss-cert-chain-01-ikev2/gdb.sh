ipsec stop
rm -f typescript
script --command "gdb -x gdb.ini"
sed -i -e 's/\r//g' -e 's/\c[[^m]*m//g' typescript
