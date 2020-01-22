# remove all dates used in ipsec auto --listall. there are three forms that appear:
# Mon Jan 20 12:54:56 UTC 2020
# Mon Oct 13 15:14:00 2015
# Oct 13 15:14:00 2015
#
s/\(Mon\|Tue\|Wed\|Thu\|Fri\|Sat\|Sun\) ... .. ..:..:.. ... 20../TIMESTAMP/g
s/\(Mon\|Tue\|Wed\|Thu\|Fri\|Sat\|Sun\) ... .. ..:..:.. 20../TIMESTAMP/g
s/\(Jan\|Feb\|Mar\|Apr\|May\|Jun\|Jul\|Aug\|Sep\|Oct\|Nov\|Dec\) .. ..:..:.. 20../TIMESTAMP/g
s/expires in [0-9]* days/expires in X days/g
# lie!
s/expires in [0-9]* hours/expires in X days/g
