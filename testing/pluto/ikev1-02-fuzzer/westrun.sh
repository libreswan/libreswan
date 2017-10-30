echo "Sending known bad packet"
ike-scan -v  --retry 3 --backoff=1 --interval=10 --trans="(1=7,14=128,2=1,3=1,4=14)" --trans="(3=1,4=14)"   192.1.2.23 | sed -e "s/in .[^ ]* /in XX /" -e "s/([^ ]* hosts/(XX.XX hosts/" -e "s/HDR=.*$/HDR=XXXXX/"
echo "Running a fuzzing scan"
./ike-scan.sh > OUTPUT/fuzz.log
echo done
