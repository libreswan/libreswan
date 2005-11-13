proc is_null_pointer {pointer} {
    if {[string length $pointer] == 0 || $pointer == "NULL"} {
	return 1
    }
    return 0
}

proc is_ipsec_sa_established {state} {
    global STATE_MAIN_R2 STATE_AGGR_R0 STATE_AGGR_I1

    if {[string length $state] == 0} {
	return 0
    }

    set st_state [state_st_state_get $state]

    if { ($STATE_MAIN_R2 <= $st_state) && ($STATE_AGGR_R0 != $st_state) && ($STATE_AGGR_I1 != $st_state)} {
	return 1
    } {
	return 0
    }
}

proc processRawPacket {state conn md} {
    set iface_port [msg_digest_iface_get  $md]
    set iface_dev  [iface_port_ip_dev_get  $iface_port]
    set if_name    [iface_dev_id_rname_get $iface_dev]
    set ipl        [addrtot [iface_port_ip_addr_get $iface_port] 0 1024]
    set ip         [lindex $ipl 1]
    puts stderr "md: $md"
    puts stderr "tcl says packet from: $ip"
}

proc recvMessage {state conn md} {
    puts stderr "recvMessage $state $conn $md"
}

proc changeState {state conn md} {
    puts stderr "changeState $state $conn $md"
}

proc adjustFailure {state conn md} {
    global STATE_QUICK_I1
    puts stderr "adjustFailure $state $conn $md"

    if {[is_null_pointer $state]} {
	return
    } {
	set st_state [state_st_state_get $state]
    }

    puts stderr "adjustFailure $state $conn $md: state $st_state"

    if {$st_state == $STATE_QUICK_I1} {
	# look up the IPsec SA details
	set ipi        [state_st_esp_get $state]
	set ourspi     [ipsec_proto_info_our_spi_get $ipi]
	set ita        [ipsec_proto_info_attrs_get $ipi]
	set hisspi     [ipsec_trans_attrs_spi_get $ita]
	set transid    [ipsec_trans_attrs_transid_get $ita]
	set keymat_len [ipsec_proto_info_keymat_len_get $ipi]
	set our_keymat_ptr [ipsec_proto_info_our_keymat_get $ipi]
	set peer_keymat_ptr [ipsec_proto_info_peer_keymat_get $ipi]
	set our_keymat  [cdata $our_keymat_ptr  $keymat_len]
	set peer_keymat [cdata $peer_keymat_ptr $keymat_len]
	openswan_DBG_dump [format "outspi: 0x%08x" $ourspi] $our_keymat
	openswan_DBG_dump [format " inspi: 0x%08x" $hisspi] $peer_keymat
    }
    
}

