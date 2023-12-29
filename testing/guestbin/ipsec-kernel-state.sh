#!/bin/sh

exec $(dirname $0)/ipsec-kernel.sh state "$@"
