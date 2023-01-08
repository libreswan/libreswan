# Remove extra jibberish added by name spaces vis:
#   ESC]0;root@HOST:/PATH/testing/pluto/TEST^G[root@GUEST TEST]#

# 1B=ESC \a=BEL \c[ doesn't seem to work
s;\x1B.*\a;;
s;\x1B.*\x1B\\;;

# trim the prompt back to 'GUEST #'

s/\[root@\([^ ]*\) .*\]# /\1 # /

# if it is a double prompt vis:
#   west # netbsdw# ...
# leave it to guest-prompt-double.sed

/^[a-z][a-z]* # [a-z][a-z]*# / {
  b
}

# if the line is blank, delete it
/^[^ ]* # $/d

# ... else add in a new line; why?
s/^\([^ ]*\) # /\1 #\n /
