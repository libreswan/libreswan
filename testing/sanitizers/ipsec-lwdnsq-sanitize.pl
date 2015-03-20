#!/usr/bin/perl

# when we get records from lwdnsq, we may well get SIG records that may
# change over time. Their existance is important, but the date and
# signature need to be sanitized

while(<>) {
# 12334 3145915 0 SIG KEY 1 4 604800 20130218000353 20030221000353 6142 uml.freeswan.org. hkNfQdwTIM93D2zBfeLH1yCWWz8VMkfOlAiZVE24o6HX4kxlb4TxXNQ5 I1A6cjQ5rbT0mPj/zDqO7MgDcjiKVA==

	s/(\d+ 3145915 0 SIG \S* 1 4 604800 )(\d+) (\d+) 6142 (.*)\. (.*)$/${1}20130218000353 20030221000353 6142 ${4}. SIGNATURE/;
	print;
}

