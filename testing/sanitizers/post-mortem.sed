# The post-mortem output is accumulated in the "pattern space".
# Should the end marker be missing (i.e., EOF reached) then
# unsanitized contents of the "pattern space" get dumped to stdout.

/>>>>>>>>>> post-mortem >>>>>>>>>>/ b post-mortem
b skip

:post-mortem
  N
  /<<<<<<<<<< post-mortem <<<<<<<<<</ b end
  b post-mortem

:end
  s/>>>>>>>>>> post-mortem >>>>>>>>>>.*<<<<<<<<<< post-mortem <<<<<<<<<<//

:skip
