# Strip out bogus backtraces about failing to disable the ethernet
# interface's LR0 when run on a VM.  This needs to run after kernel
# messages have been cleaned up.

/\[ 00.00\] ------------\[ cut here \]------------/ {
    ## a CUT HERE
    # append next line to pattern space
    N
    /\[ 00.00\] netdevice: [^:]*: failed to disable LRO!/ {
        ## a FAILED TO DISABLE
        b match-failed-to-disable-lr0
    }
    # print two lines in pattern space, then start again
    b end-failed-to-disable-lr0
}

b end-failed-to-disable-lr0

:match-failed-to-disable-lr0
  N
  /\[ 00.00\] ---\[ end trace [^ ]* \]---/ {
    # drop this final line, start from scratch
    ## a END TRACE
    d
  }
b match-failed-to-disable-lr0

:end-failed-to-disable-lr0
