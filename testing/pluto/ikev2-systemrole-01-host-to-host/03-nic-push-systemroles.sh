# nic is used as the System Role provisioning host
/testing/guestbin/nic-vpn-role-tmp
ansible-playbook --skip-tags packages -i ansible-inventory.yml test-east-west.yml 2>&1 | tee OUTPUT/ansible.out | grep -v DEPRECATED | tail -3 | sort

