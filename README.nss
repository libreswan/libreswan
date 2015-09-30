
#########################################################################
# Using the NSS crypto library with Pluto (Libreswan)
# Based on initial documentation by Avesh Agarwal <avagarwa@redhat.com>
#########################################################################

For detailed developer information about NSS, see
http://www.mozilla.org/projects/security/pki/nss/

The NSS crypto library is user space library. It is only used with the
libreswan userspace IKE daemon pluto for cryptographic operations. NSS
does not perform IPsec crypto operations inside the kernel (KLIPS
nor NETKEY)

The NSS library exports a PKCS#11 API for the application to
communicate to a cryptographic device. The cryptographic device is
usually the "soft token" but can also be a Hardware Security Module
(HSM).

The advantage of using NSS is that pluto does need to know in detail how
the cryptographic device works. Pluto does not access any private keys or
data itself. Instead, it uses the PK11 wrapper API of NSS irrespective
of the cryptographic device used. Pluto hands over work using the PK11
interface to NSS and never has direct access to the private key material
itself. Both IKEv1 and IKEv2 operations are performed using NSS. Private
RSA keys (raw RSA as well as X.509 based private RSA keys) are stored
inside NSS. RSA keys are still referenced in /etc/ipsec.secrets. X.509
keys and certificates are referenced using their "nickname" instead of
their filename in /etc/ipsec.conf.

While PreShared Key (PSK) calculations are done using NSS, the actual
preshared key ("secret") is still stored in /etc/ipsec.secrets.

NSS as shipped by Red Hat is a FIPS certified library. Libreswan is
currently being FIPS certified for RHEL7.

#########################################################################
# The NSS command line tools used with libreswan
#########################################################################

- certutil: Look and modify the NSS db. "ipsec initnss" and "ipsec look"
  use certutil under the hood.

http://www.mozilla.org/projects/security/pki/nss/tools/certutil.html

- pk12util: import and export certificates and keys from and to the NSS db.
  The "ipsec import" command is a simple wrapper around this utility.

http://www.mozilla.org/projects/security/pki/nss/tools/pk12util.html

- modutil: Put NSS into FIPS mode

http://www.mozilla.org/projects/security/pki/nss/tools/modutil.html

#########################################################################
# Creating the NSS db for use with libreswan's pluto IKE daemon
#########################################################################

If you are not using a packaged libreswan version, you might need to
create a new NSS db before you can start libreswan. This can be done
using:

	ipsec initnss

By default the NSS db is created in /etc/ipsec.d/

When creating a database, you are prompted for a password. The default
libreswan package install for RHEL/Fedora/CentOS uses an empty password.
It is up to the administrator to decide on whether to use a password
or not. However, a non-empty database password must be provided when
running in FIPS mode.

To change the empty password, run:

	certutil -W -d sql:/etc/ipsec.d

Enter return for the "old password", then enter your new password.

If you create the database with a password, and want to run NSS in FIPS
mode, you must create a password file with the name "nsspassword" in
the /etc/ipsec.d direcotry before starting libreswan. The "nsspassword"
file must contain the password you provided when creating NSS database.

If the NSS db is protected with a non-empty password, the "nsspassword"
file must exist for pluto to start.

The syntax of the "nsspassword" file is:

token_1_name:the_password
token_2_name:the_password

The name of NSS softtoken (the default software NSS db) when NOT running
in FIPS mode is "NSS Certificate DB". If you wish to use software NSS
db with password "secret", you would have the following entry in the
nsspassword file:

NSS Certificate DB:secret

If running NSS in FIPS mode, the name of NSS softtoken is
"NSS FIPS 140-2 Certificate DB". If there are smartcards in the system, the
entries for passwords should be entered in this file as well.

Note: do not enter any spaces before or after the token name or password.

#########################################################################
# Using raw RSA keys with NSS
#########################################################################

The "ipsec newhostkey" and "ipsec rsasigkey" utilities are used for
creating raw RSA keys. If a non-default NSS directory is used, this can
be specified using the -d option.

	ipsec newhostkey --configdir /etc/ipsec.d [--password password] \
		--output /etc/ipsec.secrets

The password is only required if the NSS database is protected with a
non-empty password.  All "private" compontents of the raw RSA key in
/etc/ipsec.secrets such as the exponents and primes are filled in with
the CKA ID, which serves as an identifier for NSS to look up the proper
information in the NSS db during the IKE negotiation.

Public key information is directly available in /etc/ipsec.secrets and the
"ipsec showhostkey" command can be used to generate left/rightrsasigkey=
entries for /etc/ipsec.conf.

#########################################################################
# Using certificates with NSS
#########################################################################

Any X.509 certificate management system can be used to generate Certificate
Agencies, certificates, pkcs12 files and CRLs. Common tools people use are
the openssl command, the GTK utility tinyca2, or the NSS certutil command.

An example using openssl can be found as part of the libreswan test suite at
https://github.com/libreswan/libreswan/tree/master/testing/x509

Below, we will be using the nss tools to generate certificates

* To create a certificate authority (CA certficate):

	certutil -S -k rsa -n "ExampleCA" -s "CN=Example CA Inc" -w 12 \
		-t "CT,," -x -d sql:/etc/ipsec.d

It creates a certificate with RSA keys (-k rsa) with the nick name
"ExampleCA", and with common name "Example CA Inc". The option
"-w" specifies the certificates validy period. "-t" specifies the attributes
of the certificate. "C" is required for creating a CA certificate. "-x" mean
self signed. "-d" specifies the path of the database directory. The directory
path should be prefixed with 'sql:' in order to use the SQLite format.

NOTE: It is not a requirement to create the CA in NSS database. The CA
certificate can be obtained from anywhere in the world.

* To create a user certificate signed by the above CA

	certutil -S -k rsa -c "ExampleCA" -n "user1" -s "CN=User Common Name" \
		-w 12 -t "u,u,u" -d sql:/etc/ipsec.d

It creates a user cert with nick name "user1" with attributes
"u,u,u" signed by the CA cert "ExampleCA".

NOTE: You must provide a nick name when creating a user certificate,
because pluto reads the user certificate from the NSS database based on
the user certificate's nickname.


#########################################################################
# Configuring certificates in ipsec.conf and ipsec.secrets
#########################################################################

In ipsec.conf, the leftcert= option takes a certificate nickname as argument.
For example if the nickname of the user cert is "hugh", then it can be
"leftcert=hugh".

NOTE: if you are migrating from openswan, you are used to specifying
a filename for the leftcert= option. Filenames
are not valid for the left/rightcert= options in libreswan.

In ipsec.secrets, we need to list the certificate nickname to inform pluto
there is a certificate within the NSS db.
This is specified using:

 : RSA nickname

NOTE: In openswan and freeswan  it was required to specify a file name or
password. With libreswan, this is not required.
NOTE: openswan and freeswan stored private keys in /etc/ipsec.d/private/
This directory does not exist for libreswan.

The directories /etc/ipsec.d/cacerts/ and /etc/ipsec.d/crls/ can still be used.

NOTE: the freeswan and openswan directories /etc/ipsec.d/aacerts/ and
/etc/ipsec.d/acerts/ are not used with libreswan.

If you use an external CA certificate, you can either import it into
the NSS db or place it in the /etc/ipsec.d/cacerts/ directory. Note that
the preferred method is to store it inside the NSS db.

#########################################################################
# Importing third-party certificates into NSS
#########################################################################

If you do not have the third-party certificate in PKCS#12 format, use openssl
to create a PKCS#12 file:

	openssl pkcs12 -export -in cert.pem -inkey key.pem \
		-certfile cacert.pem -out certkey.p12   [-name YourName]

Now you can import the file into the NSS db:

	ipsec import certkey.p12

NOTE: the ipsec command uses "pk12util -i certkey.p12 -d /etc/ipsec.d"

If you did not pick a name using the -name option, you can use
certutil -L -d /etc/ipsec.d to figure out the name NSS picked durnig
the import.

Add following to /etc/ipsec.secrets file:

	: RSA "YourName"

To specify the certificate in ipsec.conf, use a line like:

	leftcert=YourName

#########################################################################
# Exporting a CA(?) certificate to load on another libreswan machine
#########################################################################


Paul: wouldn't this also include the private key which we don't want?????
Paul: add "ipsec export" ?

To export the CA certificate:

	NSS_DEFAULT_DB_TYPE="sql:" pk12util -o cacert1.p12 -n cacert1 -d /etc/ipsec.d

Copy the file "cacert1.p12" to the new machine and import it using:

	ipsec import cacert1.p12
	certutil -M -n cacert1 -t "CT,," -d sql:/etc/ipsec.d

Example connection for ipsec.conf:

conn pluto-1-2
	left=1.2.3.4
	leftid="CN=usercert1"
	leftrsasigkey=%cert
	leftcert=usercert1
	right=5.6.7.8
	rightid="CN=usercert2"
	rightrsasigkey=%cert
	auto=add

#########################################################################
# Configuring a smartcard with NSS
#########################################################################

Required library: libcoolkey

To make smartcard tokens visible through NSS

	modutil -add <module_name> -libfile libcoolkeypk11.so \
		-dbdir <nss_database_dir_name> \
		-mechanisms  <mechanisms_separted_by_colons>

An example of mechanisms can be
RC2:RC4:DES:DH:SHA1:MD5:MD2:SSL:TLS:AES:CAMELLIA.

To check whether the token is visible or not, please run

	modutil -list -dbdir <nss_database_dir_name>
