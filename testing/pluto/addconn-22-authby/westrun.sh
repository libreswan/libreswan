# these should load properly

add() ( name=$1 ; shift ; set -x ; ipsec addconn --name ${name} "$@" ; )
authby() ( name=$1 ; shift ; add authby=${name} authby=${name} "$@" ; )
leftauth() ( name=$1 ; shift ; add leftauth=${name} leftauth=${name} "$@" ; )

add defaults

authby null
authby secret

authby never # fail
authby never type=drop

authby eaponly # fails
authby eaponly leftautheap=tls rightautheap=tls # should probably fail
leftauth eaponly leftautheap=tls

authby eddsa

authby ecdsa
authby ecdsa-sha2
authby ecdsa-sha2_256
authby ecdsa-sha2_384
authby ecdsa-sha2_512
authby ecdsa-sha2_256,ecdsa-sha2_384,ecdsa-sha2_512 # merges

authby rsa
authby rsasig
authby rsa-sha1
authby rsa-sha2
authby rsa-sha2_256
authby rsa-sha2_384
authby rsa-sha2_512
authby rsa-sha1,rsa-sha2
authby rsa-sha2_256,rsa-sha2_384,rsa-sha2_512

# these pass but should fail

authby rsa,secret

ipsec status | grep ' policy: '

# these should fail to load

add ikev1-rsa-sha2 authby=rsa-sha2 keyexchange=ikev1
add ikev1-ecdsa authby=ecdsa keyexchange=ikev1
add ikev1-eddsa authby=eddsa keyexchange=ikev1
