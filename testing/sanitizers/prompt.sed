#!/bin/sed

#
# Strip out cut/tuc commands
#
# Since the prompt hasn't yet been split across two lines, this will
# delete the prompts as well.

/==== cut ====/,/==== tuc ====/ d
# see DONE in KVMRUNNER and NSRUN
s/>>>>>>>>>>cut>>>>>>>>>> [^ ]* <<<<<<<<<<tuc<<<<<<<<<<//g
# see KVMRUNNER
/>>>>>>>>> post-mortem >>>>>>>>>>/,/<<<<<<<<<< post-mortem <<<<<<<<<</ d
# see NSRUN
s/>>>>>>>>>>cutnonzeroexit>>>>>>>>>>.*<<<<<<<<<<tuc<<<<<<<<<<//g


#
# Remove extra jibberish added by name spaces vis:
#   ESC]0;root@HOST:/PATH/testing/pluto/TEST^G[root@GUEST TEST]#
# 1B=ESC \a=BEL \c[ doesn't seem to work

s;\x1B.*\a;;
s;\x1B.*\x1B\\;;

#
# Reduce the prompt to:
#   [HOST]# COMMAND

s/\[root@\([^ ]*\) .*\]# /[\1]# /


#
# deal with === end ===
#
# This should leave the prompt behind, but currently it doesn't.
#

/==== end ====/,$ d
# /==== end ====/ {
#     s/\(\[[a-z][a-z]*\]\)# .*/\1# /
#     q
#}


#
# Strip out any empty commands (but not for the last prompt)

$! { /^\[\([a-z][a-z]*\)\]# $/d }


#
# Now split:
#   [HOST]# COMMAND
# into the two line:
#   HOST #
#    COMMAND
# Why?  Perhaps it is so that the pattern:
#    /^ COMMAND/,/^HOST #/ { do stuff }
# works?

s/^\[\([a-z][a-z]*\)\]# /\1 #\n /
