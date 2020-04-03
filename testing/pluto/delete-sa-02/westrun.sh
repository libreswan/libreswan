ipsec auto --up west-east
# enable sending a bogus Notify with the Delete
ipsec whack --debug-all --impair ikev1-del-with-notify
ipsec auto --down west-east
