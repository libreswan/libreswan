# replay-window will show up as 0 when ESN is enabled due to kernel bug.
ip xfrm state |grep replay-window
