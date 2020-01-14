# Remove extra jibberish added by name spaces vis:
#   ESC]0;root@HOST:/PATH/testing/pluto/TEST^G[root@GUEST TEST]#

# 1B=ESC \a=BEL \c[ doesn't seem to work
s;\x1B.*\a;;
s;\x1B.*\x1B\\;;

# trim the prompt back to 'GUEST #'

s/\[root@\([^ ]*\) .*\]# /\1 # /

# if the line is blank, delete it
/^[^ ]* # $/d

# add in a new line; why?

s/^\([^ ]*\) # /\1 #\n /
