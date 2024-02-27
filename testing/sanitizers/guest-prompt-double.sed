# guest-prompt-sanitize contains a rule to remove blank lines.  The
# below, because it appears late in the sanitize pipeline, is doing
# something different.

# For instance, the raw input with no blank lines such as:

#    [root@east]# : ==== cut ====
#    [root@east]# COMMAND-1
#    OUTPUT-1
#    [root@east]# : ==== tuc ====
#    [root@east]# COMMAND-2
#    OUTPUT-2

# will have been munged into:

#    east #
#    east #
#     COMMAND-2
#    OUTPUT-2

# by the time it reaches this script - giving the impression that
# there were blank lines when there weren't; correct fix is to dump
# the line splitting but that is another story

# new prompt in all.verbose.txt, is not split: west# ...
/^[a-z][a-z]*# / b newprompt

# form THIS-LINE\nNEXT-LINE
$ ! N

# if  THIS-LINE != NEXT-LINE; print up to \n (THIS-LINE) and re-start
/^\(\(east\|west\|road\|north\|nic\) #\)\n\1$/ ! P

# delete up to \n (THIS-LINE)
D

:newprompt
