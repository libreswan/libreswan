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

authby secret
authby psk
authby rsa

# multiple authentications

authby rsa,secret
authby secret,rsa

# keyexchange=ikev1 ignored; requires type=drop

authby never
authby never type=drop
authby never,secret type=drop

# {left,right}authby= trumps auth=

authby rsa leftauthby=secret rightauthby=secret
conn leftright leftauthby=rsa rightauthby=rsasig

# conflict because rightauthby=rsa

authby rsa leftauthby=secret

# IKEv2 only

authby digsig
authby null
authby eaponly
authby eddsa
authby ecdsa
authby rsa-sha1
authby rsa-sha2
authby digsig
leftauth rsa
