Title: Using NSS crypto library with Pluto (Libreswan)
Author: Avesh Agarwal email: avagarwa@redhat.com

About NSS crypto library
--------------------------
Please visit http://www.mozilla.org/projects/security/pki/nss/
 
NSS crypto library is user space library. It is only used with Pluto (user
space IKE daemon) for cryptographic operations. When using NSS, it does not
impact the way IPSEC kernel (KLIPS or NETKEY) works. The usefulness of using
NSS lies in the fact that the secret information (like private keys or
anything else) never comes out of NSS database. Libreswan with NSS supports
IKEV1, IKEv2, authentication using PSK, Raw RSA Sig key, and Digital Certs.


How to enable NSS crypto library with Libreswan
-----------------------------------------------
Change the flag USE_LIBNSS in libreswan/Makefile.inc to "true" before
compilation.


Basic NSS tools required
-------------------------
certutil: To create/modify/delete NSS db, certificates etc. More description
can be found at
http://www.mozilla.org/projects/security/pki/nss/tools/certutil.html

pk12util: To import/export certificates or keys in to/out of NSS db. More
description can be found at
http://www.mozilla.org/projects/security/pki/nss/tools/pk12util.html  

modutil: To put NSS into FIPS mode. 
http://www.mozilla.org/projects/security/pki/nss/tools/modutil.html


Creating database before using NSS with Pluto (Libreswan)
--------------------------------------------------------
You must create a NSS db before running pluto with NSS enabled. NSS db can be
created as follows.

certutil -N -d <path-to-ipsec.d- dir>/ipsec.d

By default the path to ipsec.d is set to /etc/ipsec.d. 

Without loss of generality, the further discussion is based on that the path
to ipsec.d is "/etc/ipsec.d".


NSS database password
----------------------
When creating a database, the certutil command also prompts for a password. It
is upto the user to provide a password or not for the database.

However, database password must be provided in FIPS mode. 


About the password file "nsspassword"
-------------------------------------
If you create the database with a password, and want to run NSS in FIPS mode,
you must create a password file with the name "nsspassword" in the
/etc/ipsec.d before running pluto with NSS. The "nsspassword" file must
contain the password you provided when creating NSS database. 

Important thing to note: 
i) You only need the "nsspassword" file if you run pluto in FIPS. In other way,
if you run pluto in normal or NonFIPS mode, then you can create the NSS
database without password, and you need not create a "nsspassword" file.
However, if the NSS db is created with a password, the "nsspassword" file must
also be provided.

ii) An example of nsspassword file is as follows:

token_1_name:its_password
token_2_name:its_password  

For example, the name of NSS softtoken (or NSS database) is
"NSS Certificate DB" in NonFIPS mode, and assume that its password is xyz.
So an entry for this in nsspassword file can be: 

NSS Certificate DB:xyz

Please note that if FIPS mode is set, then the name of NSS softtoken is 
"NSS FIPS 140-2 Certificate DB". If there are smartcards in the system, there 
entries for passwords should also be entered in this file. Please note, that 
there should not be any blank space before the token name, before and after 
colon and after the password.


Generating RSA keys when using NSS
-----------------------------------
You can still use ipsec newhostkey and ipsec rsasigkey tools for creating RSA
keys. The only difference is that you need to provide a path to NSS db
directory (or config directoty). Assuming that NSS db is is "/etc/ipsec.d", an
example is as follows

ipsec newhostkey --configdir /etc/ipsec.d [--password password] --output \
 /etc/ipsec.d/ipsec.secrets 

A password is only required if NSS database created with password. If you use
NSS and create RSA keys (private/public), you will notice that the contents of
the ipsec.secrets are different than what used to be before. 

Public key information in ipsec.secrets is stored in the same way as before.
However, all the fields of the Private key information contain just a similar
ID. This ID is called CKA ID, which is used to locate private keys inside NSS
database during the IKE negotiation.

Important thing to note
------------------------
It means that ipsec.secrets does not contain any real private key information,
as private key never comes out of NSS database. Therefore ipsec.secrets is not
really a secret file anymore when using pluto with NSS. 

ipsec.conf does not require any changes the way it is configured when using RSA
sig keys with Pluto.


Creating certificates with NSS
-------------------------------
i)To create a certificate authority (CA certficate):

certutil -S -k rsa -n <ca-cert-nickname> -s "CN=ca-cert-common-name" -w 12 \
 -d . -t "C,C,C" -x -d /etc/ipsec.d

It creates a certificate with RSA keys (-k rsa) with the nick name
"ca-cert-nickname", and with common name "ca-cert-common-name". The option
"-w" specifies the certificates validy period. "-t" specifies the attributes
of the certificate. "C" is require for creating a CA certificate. "-x" mean
self signed. "-d" specifies the path of the database directory.

Important thing to note: It is not a requirement to create the CA in NSS
database. The CA certificate can be obtained from anywhere in the world.

ii) To create a user certificate signed by the above CA

certutil -S -k rsa -c <ca-cert-nickname> -n <user-cert-nickname> \
 -s "CN=user-cet-common-name" -w 12 -t "u,u,u" -d /etc/ipsec.d 

It creates a user cert with nick name "user-cert-nickname" with attributes
"u,u,u" signed by the CA cert "ca-cert-name". 

Important thing to note: You must provided a nick name when creating a user
cert, because Pluto reads the user cert from the NSS database nased on
the user cert's nickname. 


Changes in the certificates usage with Pluto
------------------------------------------------
1) ipsec.conf changes

The only change is "leftcert" field must contain the nick name of the user
cert. For example if the nickname of the user cert is "xyz", then it can be
"leftcert=xyz".

2) ipsec.secrets changes

 : RSA <user-cert-nick-name> 

You just need to provide the user cert's nick name. For example if the nickname
of the user cert is "xyz", then

 : RSA xyz 

There is no need to provide private key file information or its password. 

3) changes in the directories in /etc/ipsec.d/ (cacerts, certs, private)  
i)You need not have "private" or "certs" directory.

ii) If you obtain a CA certificate from outside, and it is not inside NSS
database, then you need to put the certificate inside "cacerts" directory, so
that Pluto can read it. If the CA certificate is created in the NSS database,
or imported from outside inside the NSS database, you need not have "cacerts"
directory, as Pluto can read the CA cert from the database.

Migrating Certificates
----------------------
openssl pkcs12 -export -in cert.pem -inkey key.pem -certfile cacert.pem \
 -out certkey.p12

You will get one file in PKCS#12 format containing all the required
information. You could also use -name parameter to give a name to the
certificate. If you leve it empty the following nss utils will pick one from
the data in certificate.

export NSS_DEFAULT_DB_TYPE="sql"
# To use sql format of nss db which fedora's libreswan expects.

certutil -N -d /etc/ipsec.d
# Use empty passwords.

pk12util -i certkey.p12 -d /etc/ipsec.d
# Remember the name of the imported certificate pk12utils picked, if you
# specified it before it should be the same, if not the util picked one.

Add following to /etc/ipsec.secrets file:
: RSA "name of certificate in nss db" ""

Edit your connection and replace the leftcert/rightcert with the certifiate
name with the same name of certificate in nss db.

An example Scenario: To setup ipsec with certs in tunnel mode using NSS
------------------------------------------------------------

GW Machine 1: w1.x1.y1.z1 
GW Machine 2: w2.x2.y2.z2 

w1.x1.y1.z1 <---> w2.x2.y2.z2

Note: In this example setup, both machines are using NSS. If you want to use
NSS only at one machine, say machine 1, you can use the following procedure
only at machine 1, and you can use traditional ipsec setup at machine 2.

1. Create a new (if not already) nss db on both machines as follows:

certutil -N -d <path-to-ipsec.d dir>/ipsec.d

2. Creating CA certs at both machines:

On machine 1:
certutil -S -k rsa -n cacert1 -s "CN=cacert1" -v 12 -d . -t "C,C,C" -x -d \
 <path-to-ipsec.d dir>/ipsec.d

As we want to use the same certificate  "cacert1" at machine 2, it needs to be
exported first. To export the cacert1, do the following at machine 1:

pk12util -o cacert1.p12 -n cacert1 -d /etc/ipsec.d

Copy the file "cacert1.p12" to the machine2 in "/etc/ipsec.d" directory.

On machine 2:
Import the "cacert1" as follows:

cd /etc/ipsec.d
pk12util -i cacert1.p12 -d /etc/ipsec.d
certutil -M -n cacert1 -t "C,C,C" -d /etc/ipsec.d

Now machine 2 also has the CA certificates "cacert1" in its NSS database.

3. Creating user certs at both machines:

On machine 1:
certutil -S -k rsa -c cacert1 -n usercert1 -s "CN=usercert1" -v 12 -t "u,u,u" \
 -d /etc/ipsec.d
(Note this cert is signed by "cacert1")

On machine 2:
certutil -S -k rsa -c cacert1 -n usercert2 -s "CN=usercert2" -v 12 -t "u,u,u" \
 -d /etc/ipsec.d
(Note this cert is signed by "cacert1" too)

4. Preparing ipsec.conf at both machines

ipsec.conf at machine 1:


conn pluto-1-2
	left=w1.x1.y1.z1
	leftid="CN=usercert1"
	leftrsasigkey=%cert
	leftcert=usercert1
	right=w2.x2.y2.z2
	rightid="CN=usercert2"
	rightrsasigkey=%cert
	rekey=no
	esp="aes-sha1"
	ike="aes-sha1"
	auto=add


ipsec.conf at machine 2:


conn pluto-1-2
	left=w2.x2.y2.z2
	leftid="CN=usercert2"
	leftrsasigkey=%cert
	leftcert=usercert2
	right=w1.x1.y1.z1
	rightid="CN=usercert1"
	rightrsasigkey=%cert
	rekey=no
	esp="aes-sha1"
	ike="aes-sha1"
	auto=add

5. Preparing ipsec.secrets at both machines 

ipsec.secrets at machine 1:

 : RSA usercert1


ipsec.secrets at machine 1:

 : RSA usercert2

Configuring a smartcard with NSS
---------------------------------
Required library: libcoolkey

To make smartcard tokens visible through NSS

modutil -add <module_name> -libfile libcoolkeypk11.so -dbdir \
 <nss_database_dir_name> -mechanisms  <mechanisms_separted_by_colons> 

An example of mechanisms can be
RC2:RC4:DES:DH:SHA1:MD5:MD2:SSL:TLS:AES:CAMELLIA.

To check whether the token is visible or not, please run

modutil -list -dbdir <nss_database_dir_name>
