# nic is used as the System Role provisioning host
ansible-playbook --skip-tags packages -i ansible-inventory.yml test-east-west.yml > OUTPUT/ansible.out 2>&1
grep -e '^ok:.*>' OUTPUT/ansible.out
