# both ESN_NO and ESN_YES should show up
ipsec status | grep ESN_
# replay-window will show up as 0 when ESN is enabled, while replay_window shows the real value
ipsec _kernel state | grep replay
