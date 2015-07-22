proc hexdump_pb {prefix pb} {

    set pb_size [pbs_offset_get $pb]
    puts stderr "$prefix size: $pb_size"

    for {set i 0} {$i < $pb_size} {set i [expr $i + 8]} {
	set line [format "%04d: %02x %02x %02x %02x  %02x %02x %02x %02x" \
		      $i \
		      [pbs_peek $pb [expr $i + 0]]		\
		      [pbs_peek $pb [expr $i + 1]]		\
		      [pbs_peek $pb [expr $i + 2]]		\
		      [pbs_peek $pb [expr $i + 3]]	        \
		      [pbs_peek $pb [expr $i + 4]]		\
		      [pbs_peek $pb [expr $i + 5]]		\
		      [pbs_peek $pb [expr $i + 6]]		\
		      [pbs_peek $pb [expr $i + 7]]]

	puts stderr "$prefix $line"
    }
}

proc hack_sa_payload {sapb} {
    set propMax [expr [pbs_offset $sapb] - 8]
    set newsapb [pbs_create [expr [pbs_offset $sadb] + 32]]

    # copy the header
    pbs_append $newsapb 0 $sapb 0 8
    set paylengthloc 2
}

#
# this inserts the VID at the beginning of the packet.
#
proc insertVendorId {msg vendorid} {
    set len [pbs_offset_get $msg]
    set vidlen [expr ([string bytelength $vendorid] + 7) & 0xfffc]
    set newpb [pbs_create [expr $len + $vidlen]]

    puts stderr "Inserting VID($vidlen): $vendorid"

    # copy IKE header
    pbs_append $newpb 0 $msg 0 28
    set inLoc  28
    set outLoc 28

    set thispay [pbs_peek $msg 16]
    set thispayloc 16

    # copy the first payload if HASH or SA, since VID can not be first, cf:
    #   rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode

    global ISAKMP_NEXT_SA ISAKMP_NEXT_HASH
    for {} {$thispay == $ISAKMP_NEXT_SA || $thispay == $ISAKMP_NEXT_HASH} {} {
	set nextpay [pbs_peek $msg $inLoc]
	set nextpayloc $inLoc
	set paylen  [expr ([pbs_peek $msg [expr $inLoc + 2]] * 256) + [pbs_peek $msg [expr $inLoc + 3]]]

	puts stderr "copying payload($thispay) at $inLoc, np: $nextpay with len: $paylen"

	# copy payload to new message
	#pbs_append $newpb $outLoc $msg $inLoc $paylen
	#set outLoc [expr $outLoc + $paylen]
	
	# copy payload to new message
	set newpaypb [pbs_create [expr $paylen * 2]]
	pbs_append $newpaypb 0 $msg $inLoc $paylen

	if {$thispay == $ISAKMP_NEXT_SA} {
	    hack_sa_payload $newpaypb
	}

	# $newpaypb has the payload now.
	set newpaylen [pbs_offset_get $newpaypb]
	pbs_append $newpb $outLoc $newpaypb 0 $newpaylen
	set outLoc [expr $outLoc + $paylen]
	
	# poke payload type in pointer to this payload.
	# most of the time, a no-op.
	#puts stderr "overwrriting previous np: newpb($thispayloc)=$thispay"
	pbs_poke $newpb $thispayloc $thispay
	set thispayloc $nextpayloc

	# cut payload from $msg
	set inLoc [expr $inLoc + $paylen]

	set thispay    $nextpay
    }

    #hexdump_pb "2: " $newpb

    # insert vendor ID as np.
    global ISAKMP_NEXT_VID			
    pbs_poke $newpb $thispayloc $ISAKMP_NEXT_VID

    set preVidLoc $outLoc
    # insert our VID ID payload
    pbs_poke $newpb $outLoc $thispay
    incr outLoc
    pbs_poke $newpb $outLoc 0
    incr outLoc
    set b1 [expr $vidlen >> 8]
    set b2 [expr $vidlen & 0xff]
    puts stderr "VIDlen: $vidlen $b1 $b2"
    pbs_poke $newpb $outLoc $b1
    incr outLoc
    pbs_poke $newpb $outLoc $b2
    incr outLoc

    binary scan $vendorid c* vidbytes

    foreach byte $vidbytes {
	pbs_poke $newpb $outLoc $byte
	incr outLoc
    }
    # round up.
    set outLoc [expr $vidlen + $preVidLoc]

    #hexdump_pb "3: " $newpb

    pbs_append $newpb $outLoc $msg $inLoc [expr $len - $inLoc]
    return $newpb
}

# just before emitting the first main mode packet, hack the
# packet so that it has a gratuitous entry in the proposal, that
# picks a key size of 128 bits.
proc avoidEmitting {state conn md} {
    global STATE_MAIN_I1

    set st_state [state_st_state_get $state]

    if { ($STATE_MAIN_I1 != $st_state)} {
	return "ignore"
    }

    set pb [msg_digest_reply_get $md]

    hexdump_pb "before" $pb
    # we have the right state now.
    set newpb [insertVendorId $pb "IKEDES128HACK"]

    hexdump_pb "after " $newpb
    set pb_size [pbs_offset_get $newpb]
    pbs_append $pb 0 $newpb 0 $pb_size
    set a [expr ($pb_size >> 24) & 0xff]
    set b [expr ($pb_size >> 16) & 0xff]
    set c [expr ($pb_size >> 8)  & 0xff]
    set d [expr ($pb_size >> 0)  & 0xff]
    pbs_poke $pb 24 $a
    pbs_poke $pb 25 $b
    pbs_poke $pb 26 $c
    pbs_poke $pb 27 $d
    puts stderr "a:$a b:$b c:$c d:$d"
    puts stderr [format "hp:%08x" $pb_size]
    msg_digest_reply_set $md $pb
    hexdump_pb "pb:$pb_size " $pb
    pbs_free $pb

    return "nothing"
}

