#!/usr/bin/perl

while(<>) {
  s,^(\s*\d+)(\s+\d+\s+[dl-][rwxs-]{9}\s+\d+\s+root\s+root\s+\d+ )... [ \d]\d \d\d:\d\d( /proc/), inode\2Aug 29 22:34\3,;
  s,^([dl-][rwxs-]{9}\s+\d+\s+root\s+root\s+\d+ )... [ \d]\d \d\d:\d\d( /proc/),\1Aug 29 22:57\2,;
  print;
}
