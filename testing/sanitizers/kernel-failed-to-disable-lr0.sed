# Strip out bogus backtraces about failing to disable the ethernet
# interface's LR0 when run on a VM.  This needs to run after kernel
# messages have been cleaned up.

/\[ 00.00\] ------------\[ cut here \]------------/ {
    ## a CUT HERE
    # append next line to pattern space
    N
    /\[ 00.00\] netdevice: [^:]*: failed to disable LRO!/ {
        ## a FAILED TO DISABLE
        b failed_to_disable
    }
    # print two lines in pattern space, then start again
    b
}

b

: failed_to_disable
N
/\[ 00.00\] ---\[ end trace [^ ]* \]---/ {
    # drop this final line, start from scratch
    ## a END TRACE
    d
}
b failed_to_disable
