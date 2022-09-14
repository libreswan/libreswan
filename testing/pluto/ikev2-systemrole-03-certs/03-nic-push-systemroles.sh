# nic is used as the System Role provisioning host
ansible-playbook --skip-tags packages -i ansible-inventory.yml test-east-west.yml 2>&1 | tee OUTPUT/ansible.out | grep -v DEPRECATED | tail -3 | sort
