# The post-mortem output is accumulated in the "pattern space".
# Should the end marker be missing (i.e., EOF reached) then
# unsanitized contents of the "pattern space" get dumped to stdout.

/>>>>>>>>>> post-mortem >>>>>>>>>>/ b match-post-mortem
b skip-post-mortem

:match-post-mortem
  N
  /<<<<<<<<<< post-mortem <<<<<<<<<</ b end-post-mortem
  b match-post-mortem

:end-post-mortem
  s/>>>>>>>>>> post-mortem >>>>>>>>>>.*<<<<<<<<<< post-mortem <<<<<<<<<<//

:skip-post-mortem
