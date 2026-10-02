/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

RUN()      { echo " $@" ; "$@" ; }

policy()   { name=$1 ; shift ; ipsec connectionstatus ${name} | sed -n -e 's/.*  \(policy:.*\)/ \1/p' ; }
hash_policy()   { name=$1 ; shift ; ipsec connectionstatus ${name} | sed -n -e 's/.* \(v2-auth-hash-policy:.*\)/ \1/p' ; }
our_auth()   { name=$1 ; shift ; ipsec connectionstatus ${name} | sed -n -e 's/.* \(our auth:[^,]*\).*/ \1/p' ; }
their_auth()   { name=$1 ; shift ; ipsec connectionstatus ${name} | sed -n -e 's/.* \(their auth:[^,]*\).*/ \1/p' ; }
policies() { policy $1 ; hash_policy $1 ; our_auth $1 ; their_auth $1 ; }

add()      ( name=$1 ; shift ; RUN ipsec addconn --name ${name} "$@" ; )
del()      { name=$1 ; shift ; ipsec delete ${name} ; }
conn()     { name=$1 ; shift ; add ${name} "$@" ; policies ${name} ; del ${name} ; }
authby()   { name=$1 ; shift ; conn authby:${name}   authby=${name} "$@" ; }
leftauth() { name=$1 ; shift ; conn leftauth:${name} leftauth=${name} "$@" ; }

# these should load properly

conn defaults

authby null
authby secret
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

# keyexchange=ikev2 ignored; requires type=drop

authby never # fail
authby never type=drop
authby never,secret type=drop

# eaponly also requires *autheap

authby eaponly # fails
leftauth eaponly # fails

authby eaponly leftautheap=tls rightautheap=tls
leftauth eaponly leftautheap=tls

# these are weird sub bits

leftauth rsasig authby=rsa-sha2_256,rsa-sha2_512 #=> rsa-sha2_256,rsa-sha2_512

# these should get a warning

authby rsa,psk #=> rsa; warning: psk; FAILS TO LOAD AS PSK IS NOT VALID
authby rsa,secret #=> rsa; warning: psk; POLICY SHOWS PSK
authby rsa-sha2_256,rsa-sha2_512,secret #=> rsa-sha2_256,rsa-sha2_512; warning: psk

leftauth psk authby=rsa #=> psk; warning: rsa; WARNING SHOWS SECRET NOT PSK
leftauth secret authby=rsa #=> psk; warning: rsa
leftauth secret authby=rsa,secret #=> psk; warning: rsa; warning: rsa

authby rsa leftauthby=secret
authby rsa leftauthby=secret rightauthby=eddsa # override allowed
leftauth rsasig authby=secret leftauthby=rsa
leftauth secret leftauthby=rsasig
leftauth secret leftauthby=secret authby=rsasig
