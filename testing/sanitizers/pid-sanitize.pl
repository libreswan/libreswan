#!/usr/bin/perl

while(<>) {
  s/^(\[\d+\])\s*(\d*)$/\1 9999/;
  print;
}
