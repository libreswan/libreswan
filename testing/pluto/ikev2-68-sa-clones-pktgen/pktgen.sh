#!/bin/bash

# Number of CPUs. If you have more than 2.
CPUS=1
# Number of packets generated for each core.
PKTS=`echo "scale=0; 1000000/$CPUS" | bc`
# Number of copies of the same packet. The number 0
# will use the same packet forever.
CLONE_SKB="clone_skb 10"
# Size of a single packet.
PKT_SIZE="pkt_size 9014"
# Number of packets to send. The number 0 will send 
# packets until the user stops the stream.
COUNT="count 0"
# The transmission delay between two packets.
DELAY="delay 0"
# Get the MAC address. This case we will user eth0 
# as interface.
# if can be eth1, eth2, wlan0, wlan1, etc...
ETH="eth0"
MAC=$(ifconfig -a | grep eth0 | cut -d' ' -f 11)
# The rate of the stream.
RATEP=`echo "scale=0; 1000000000/$CPUS" | bc`


function pgset() {
    local result

    echo $1 > $PGDEV

    result=`cat $PGDEV | fgrep "Result: OK:"`
    if [ "$result" = "" ]; then
        cat $PGDEV | fgrep Result:
    fi
}

for ((processor=0;processor<$CPUS;processor++))
#for processor in {0..1}
do
    PGDEV=/proc/net/pktgen/kpktgend_$processor
    echo "Removing all devices"
    pgset "rem_device_all"
done


or ((processor=0;processor<$CPUS;processor++))
#for processor in {0..1}
do
    PGDEV=/proc/net/pktgen/kpktgend_$processor
    echo "Adding $ETH"
    pgset "add_device $ETH@$processor"
    PGDEV=/proc/net/pktgen/$ETH@$processor
    echo "Configuring $PGDEV"
    # Set the count variable defined above.
    pgset "$COUNT"
    # One queue per core.
    pgset "flag QUEUE_MAP_CPU"
    # Set the clone_skb variable defined above.
    pgset "$CLONE_SKB"
    # A packet is divided into 10 fragments.
    pgset "frags 10"
    # Set the packet size variable defined above.
    pgset "$PKT_SIZE"
    # Set the delay variable defined above.
    pgset "$DELAY"
    # Set the rate of the stream.
    pgset "ratep $RATEP"
    # Queue 2 copies of the same packet.
    pgset "burst 2"
    # Set the destination of the packets.
    # You can you use your own range of IPs.
    # IMPORTANT: be aware, you can cause a DoS attack
    # if you flood a machine with so many pack packets.
    pgset "dst 192.1.2.23"
    # Set the MAC address of the interface.
    pgset "dst_mac $MAC"
    # Random address with in the min-max range
    pgset "flag IPDST_RND"
    # Set the minimum IP address to send the packets.
    # The same as "dst" field.
    pgset "dst_min 192.1.2.23"
    # Set the maximum IP address to send the packets.
    pgset "dst_max 192.1.2.23"
    # Enable configuration packet.
    pgset "config 1"
    # 1k Concurrent flows at 8 pkts
    pgset "flows 1024"
    pgset "flowlen 8"
done

PGDEV=/proc/net/pktgen/pgctrl


