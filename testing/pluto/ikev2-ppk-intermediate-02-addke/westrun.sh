../../guestbin/pluto-up-down.sh 'ike=aes;dh20'                                   -- -I 192.0.1.254 192.0.2.254 # sanitize-retransmits
../../guestbin/pluto-up-down.sh 'ike=aes;dh20' intermediate=yes                  -- -I 192.0.1.254 192.0.2.254 # sanitize-retransmits
../../guestbin/pluto-up-down.sh 'ike=aes;dh20;addke1=none'                       -- -I 192.0.1.254 192.0.2.254 # sanitize-retransmits
../../guestbin/pluto-up-down.sh 'ike=aes;dh20;addke1=none;addke2=ml_kem_768'     -- -I 192.0.1.254 192.0.2.254 # sanitize-retransmits
../../guestbin/pluto-up-down.sh 'ike=aes;dh20;addke1=modp8192;addke2=none'       -- -I 192.0.1.254 192.0.2.254 # sanitize-retransmits
../../guestbin/pluto-up-down.sh 'ike=aes;dh20;addke1=modp8192;addke2=ml_kem_768' -- -I 192.0.1.254 192.0.2.254 # sanitize-retransmits
