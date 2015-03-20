# temp remove the klips nat-t oops from causing false positives
# [ 00.00] ------------[ cut here ]------------
# [ 00.00] ---[ end trace 91131d3946d77269 ]---
/^\[ *[0123456789]*\.[0123456789]*\] --* *\[ cut here \] *--*/,/---\[ end trace .* \]---$/d
