# remove all dates used in ipsec auto --listall. there are two forms tha tappear:
# Oct 13 15:14:00 2015
# Mon Oct 13 15:14:00 2015
#
# Someone smarter than me, please turn this into one super regexp
#
s/Jan .. ..:..:.. 20../TIMESTAMP/g
s/Feb .. ..:..:.. 20../TIMESTAMP/g
s/Mar .. ..:..:.. 20../TIMESTAMP/g
s/Apr .. ..:..:.. 20../TIMESTAMP/g
s/May .. ..:..:.. 20../TIMESTAMP/g
s/Apr .. ..:..:.. 20../TIMESTAMP/g
s/Jun .. ..:..:.. 20../TIMESTAMP/g
s/Jul .. ..:..:.. 20../TIMESTAMP/g
s/Aug .. ..:..:.. 20../TIMESTAMP/g
s/Sep .. ..:..:.. 20../TIMESTAMP/g
s/Oct .. ..:..:.. 20../TIMESTAMP/g
s/Nov .. ..:..:.. 20../TIMESTAMP/g
s/Dec .. ..:..:.. 20../TIMESTAMP/g
#
s/Mon ... .. ..:..:.. 20../TIMESTAMP/g
s/Tue ... .. ..:..:.. 20../TIMESTAMP/g
s/Wed ... .. ..:..:.. 20../TIMESTAMP/g
s/Thu ... .. ..:..:.. 20../TIMESTAMP/g
s/Fri ... .. ..:..:.. 20../TIMESTAMP/g
s/Sat ... .. ..:..:.. 20../TIMESTAMP/g
s/Sun ... .. ..:..:.. 20../TIMESTAMP/g
