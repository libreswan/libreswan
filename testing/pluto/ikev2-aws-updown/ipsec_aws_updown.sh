#!/bin/bash
case "${PLUTO_VERB}:${PLUTO_CONNECTION}" in
  route*:westnet-northnet)
    ipsec _updown
    (ipsec auto --delete eastnet-northnet; ipsec auto --add eastnet-northnet;) >/dev/null 2>&1 &
    echo "westnet-northnet routed: setting eastnet-northnet passive"
    ;;
  route*:eastnet-northnet)
    ipsec _updown
    (ipsec auto --delete westnet-northnet; ipsec auto --add westnet-northnet) >/dev/null 2>&1 &
    echo "eastnet-northnet routed: setting westnet-northnet passive"
    ;;
  down*:*)
    ipsec _updown
    ipsec auto --unroute ${PLUTO_CONNECTION} >/dev/null 2>&1 &
    echo "down: unrouting..."
    ;;
  unroute*:westnet-northnet)
    ipsec _updown
    ipsec auto --asynchronous --up eastnet-northnet >/dev/null 2>&1 &
    echo "eastnet-northnet up"
    ;;
  unroute*:eastnet-northnet)
    ipsec _updown
    ipsec auto --asynchronous --up westnet-northnet >/dev/null 2>&1 &
    echo "westnet-northnet up"
    ;;
  *)
    ipsec _updown
    ;;
esac
