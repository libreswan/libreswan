# nic is used as the System Role provisioning host
/testing/guestbin/nic-vpn-role-tmp
# save all output
ansible-playbook --skip-tags packages -i ansible-inventory.yml test-east-west.yml > OUTPUT/$(hostname).ansible.log 2>&1
sed -n -e '/PLAY RECAP/,$ p' -e '/^failed:/ p' OUTPUT/$(hostname).ansible.log
