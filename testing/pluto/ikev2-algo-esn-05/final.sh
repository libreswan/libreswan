# replay-window will show up as 0 when ESN is enabled, while replay_window shows the real value
ip xfrm state |grep replay
# should have no hits
ip xfrm state | grep replay-window |grep esn
