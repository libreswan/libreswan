s/[0-9]*-[0-9]*-[0-9]* [0-9]*:[0-9]*:[0-9]* \[INFO\]/TIMESTAMP [INFO]/
s/[0-9]*-[0-9]*-[0-9]* [0-9]*:[0-9]*:[0-9]* \[DEBUG\]/TIMESTAMP [DEBUG]/
s/,v.* Exp/ RCSVERSION/
s/starting racoon2-iked for racoon2 .*$/starting racoon2-iked for racoon2 VERSION/
# pid sanitizer
s/^[0-9]*$/PID/
s/spmd I\/F connection ok: 220 .*$/spmd I\/F connection ok: 220 HEXBLOB/
