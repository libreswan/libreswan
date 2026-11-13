ipsec replace modecfg-road-eastnet-psk
ipsec connectionstatus modecfg-road-eastnet-psk
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-eastnet-psk --initiate # sanitize-retransmits
ipsec trafficstatus
