There's recomendation (where?) that external code be kept in a
sub-directory named after the licence terms.  For instance:

   external/gpl2/linux-xfrm-headers

This way, should there be a licencing concern, tracking down and
removing the code is easier.

This directory doesn't go that far.  It instead just keeps things in
very flat sub-directories:

   external/linux-xfrm-headers
   external/pfkeyv2 (multiple licences)
