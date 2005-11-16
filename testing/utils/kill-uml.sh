#!/bin/sh 

MCONSOLE=uml_mconsole

for i in /tmp/uml/*
do
	$MCONSOLE $i/mconsole halt
done
