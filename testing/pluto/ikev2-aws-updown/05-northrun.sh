ipsec whack --impair revival
ipsec auto --up westnet-northnet

ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus

# block west ...

iptables -I INPUT -s 192.1.2.45 -j DROP
iptables -I OUTPUT -d 192.1.2.45 -j DROP

# ... west #1/#2 dies ...

../../guestbin/wait-for-pluto.sh --match '#1: ESTABLISHED_IKE_SA: .* second timeout exceeded'
../../guestbin/wait-for-pluto.sh --match '#2: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh --match '#2: down-client output: down: unrouting'
../../guestbin/wait-for-pluto.sh --match '#2: ESP traffic information'
../../guestbin/wait-for-pluto.sh --match '#1: deleting IKE SA'

# ... east #3/#4 establishes

../../guestbin/wait-for-pluto.sh --match '#3: initiating IKEv2 connection'
../../guestbin/wait-for-pluto.sh --match '#4: route-client output: eastnet-northnet routed: setting westnet-northnet passive'
../../guestbin/wait-for-pluto.sh --match '#4: initiator established Child SA using #3'

ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus

# unblock west; nothing should change

iptables -D INPUT -s 192.1.2.45 -j DROP
iptables -D OUTPUT -d 192.1.2.45 -j DROP
sleep 10 # let the liveness flow
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus

# block east ...

iptables -I INPUT -s 192.1.2.23 -j DROP
iptables -I OUTPUT -d 192.1.2.23 -j DROP

# ... east #3/#4 dies ...

../../guestbin/wait-for-pluto.sh --match '#3: ESTABLISHED_IKE_SA: .* second timeout exceeded'
../../guestbin/wait-for-pluto.sh --match '#4: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh --match '#4: down-client output: down: unrouting'
../../guestbin/wait-for-pluto.sh --match '#4: ESP traffic information'
../../guestbin/wait-for-pluto.sh --match '#3: deleting IKE SA'

# ... west #5/#6 establishes

../../guestbin/wait-for-pluto.sh --match '#5: initiating IKEv2 connection'
../../guestbin/wait-for-pluto.sh --match '#6: route-client output: westnet-northnet routed: setting eastnet-northnet passive'
../../guestbin/wait-for-pluto.sh --match '#6: initiator established Child SA using #5'

ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus

# unblock east; nothing should change

iptables -D INPUT -s 192.1.2.23 -j DROP
iptables -D OUTPUT -d 192.1.2.23 -j DROP
sleep 10 # let the liveness flow
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus

# block both

iptables -I INPUT -s 192.1.2.45 -j DROP
iptables -I OUTPUT -d 192.1.2.45 -j DROP
iptables -I INPUT -s 192.1.2.23 -j DROP
iptables -I OUTPUT -d 192.1.2.23 -j DROP

# ... west #5/#6 dies ...

../../guestbin/wait-for-pluto.sh --match '#5: ESTABLISHED_IKE_SA: .* second timeout exceeded'
../../guestbin/wait-for-pluto.sh --match '#6: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh --match '#6: down-client output: down: unrouting'
../../guestbin/wait-for-pluto.sh --match '#6: ESP traffic information'
../../guestbin/wait-for-pluto.sh --match '#5: deleting IKE SA'

ipsec whack --trafficstatus
../../guestbin/ping-once.sh --down -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --down -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus

# ... east #7 tries to establish and fails ...

../../guestbin/wait-for-pluto.sh --match '#7: initiating IKEv2 connection'
../../guestbin/wait-for-pluto.sh --match '#7: IKE_SA_INIT_I: .* second timeout exceeded'
../../guestbin/wait-for-pluto.sh --match '#7: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh --match '#7: unroute-client output: westnet-northnet up'
../../guestbin/wait-for-pluto.sh --match '#7: deleting IKE SA'

# ... west #8 tries to establish and fails ...

../../guestbin/wait-for-pluto.sh --match '#8: initiating IKEv2 connection'
../../guestbin/wait-for-pluto.sh --match '#8: IKE_SA_INIT_I: .* second timeout exceeded'
../../guestbin/wait-for-pluto.sh --match '#8: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh --match '#8: unroute-client output: eastnet-northnet up'
../../guestbin/wait-for-pluto.sh --match '#8: deleting IKE SA'

# unblock east ...

iptables -D INPUT -s 192.1.2.23 -j DROP
iptables -D OUTPUT -d 192.1.2.23 -j DROP

# ... east #9/#10 establish

../../guestbin/wait-for-pluto.sh --match '#9: initiating IKEv2 connection'
../../guestbin/wait-for-pluto.sh --match '#10: route-client output: eastnet-northnet routed: setting westnet-northnet passive'
../../guestbin/wait-for-pluto.sh --match '#10: initiator established Child SA using #9'

ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus

# unblock west; nothing should change

iptables -D INPUT -s 192.1.2.45 -j DROP
iptables -D OUTPUT -d 192.1.2.45 -j DROP
sleep 10 # let the liveness flow
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.23
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.1.4.45
ipsec whack --trafficstatus
