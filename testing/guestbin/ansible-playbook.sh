#!/bin/sh

ansible-playbook "$@" 2>&1 | \
    tee OUTPUT/$(hostname).ansible.out | \
    sed \
	-e '/DEPRECATED/d' \
	-e 's/ok=[0-9]*/ok=N/' \
	-e 's/skipped=[0-9]*/skipped=N/' \
	-e '1,/PLAY RECAP/d' | \
    sort
