# enable sending a bogus Notify with the Delete
ipsec whack --debug-all
ipsec whack --impair ikev1_del_with_notify
ipsec down west-east
