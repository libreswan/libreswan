#!/usr/bin/python
""" dist_certs.py: create a suite of x509 certificates for the Libreswan
	test harness

 Copyright (C) 2014 Matt Rogers <mrogers@redhat.com>

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the
 Free Software Foundation; either version 2 of the License, or (at your
 option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 for more details.
 """

import os
import sys
import ssl
import shutil
import subprocess
import time
from datetime import datetime, timedelta

try:
	import pexpect
	from OpenSSL import crypto
except ImportError as e:
	module = str(e)[16:]
	sys.exit("Python module %s required! " % module)

CRL_URI = 'URI:http://nic.testing.libreswan.org/revoked.crl'

dates = {}
ca_certs = {}
end_certs = {}


def reset_files():
	for dir in ['keys/', 'cacerts/', 'certs/',
			    'pkcs12/', 'pkcs12/curveca', 'crls/']:
		if os.path.isdir(dir):
			shutil.rmtree(dir)
		os.mkdir(dir)


def writeout_cert(filename, item,
				  type=crypto.FILETYPE_PEM):
	with open(filename, "w") as f:
		f.write(crypto.dump_certificate(type, item))


def writeout_privkey(filename, item,
					 type=crypto.FILETYPE_PEM):
	with open(filename, "w") as f:
		f.write(crypto.dump_privatekey(type, item))


def create_keypair(algo=crypto.TYPE_RSA, bits=1024):
	""" Create an OpenSSL keypair
	"""
	pkey = crypto.PKey()
	pkey.generate_key(algo, bits)
	return pkey


def create_csr(pkey, CN,
			   C=None, ST=None, L=None, O=None, OU=None,
			   emailAddress=None, algo='sha1'):
	""" Create the certreq
	"""
	req = crypto.X509Req()
	subject = req.get_subject()
	subject.CN = CN
	subject.C = C
	subject.ST = ST
	subject.L = L
	subject.O = O
	subject.OU = OU
	subject.CN = CN
	subject.emailAddress = emailAddress
	req.set_pubkey(pkey)
	req.sign(pkey, algo)
	return req


def set_cert_extensions(cert, issuer, isCA=False, isRoot=False):
	""" Set some cert extensions. isCA/isRoot for a few different profiles
	Some notes about these extensions
	: extensions from the testing/x509/openssl.cnf:
	: keyUsage = nonRepudiation, digitalSignature, keyEncipherment
	: extendedKeyUsage=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.3
	: subjectKeyIdentifier=hash
	: authorityKeyIdentifier=keyid,issuer:always
	: basicConstraints=CA:FALSE
	: crlDistributionPoints= CRL_URI in all
	: dontYouLoveCerts = True
	How are we supposed to specify this ldap URI with add_extensions??
	cert.add_extensions([crypto.X509Extension('crlDistributionPoints', False,
	'URI:ldap://nic.testing.libreswan.org/o=Libreswan,
	c=CA?certificateRevocationList?base?(objectClass=certificationAuthority)')])
	Can't. 1. try a raw string or something 2. time to send an email
	"""
	ku_str = 'digitalSignature,nonRepudiation,keyEncipherment'
	ski_str = 'serverAuth,clientAuth,codeSigning'
	aki_str = 'keyid:always,issuer:always'

	if isCA:
		bc = "CA:TRUE"
	else:
		bc = "CA:FALSE"
	cert.add_extensions([
		crypto.X509Extension('basicConstraints',
							 False, bc)])
	if isRoot:
		skisub = issuer
	else:
		skisub = cert
		cert.add_extensions([
			crypto.X509Extension('keyUsage',
								 False, ku_str)])
		cert.add_extensions([
			crypto.X509Extension('extendedKeyUsage',
								 False, ski_str)])
	cert.add_extensions([
		crypto.X509Extension('subjectKeyIdentifier',
							 False, 'hash', subject=skisub)])
	cert.add_extensions([
		crypto.X509Extension('authorityKeyIdentifier',
							 False, aki_str, issuer=issuer)])
	cert.add_extensions([
		crypto.X509Extension('crlDistributionPoints',
							 False, CRL_URI)])


def create_sub_cert(CN, CACert, CAkey, snum, START, END,
					C='ca', ST='Ontario', L='Toronto',
					O='Libreswan', OU='Test Department',
					emailAddress='testing@libreswan.org',
					ty=crypto.TYPE_RSA, keybits=1024,
					sign_alg='sha1', isCA=False):
	""" Create a subordinate cert and return the cert, key tuple
    This could be a CA for an intermediate, or not for an EE
	"""
	certkey = create_keypair(ty, keybits)
	certreq = create_csr(certkey,
						 CN, C, ST, L, O, OU,
						 emailAddress, sign_alg)

	cert = crypto.X509()
	cert.set_serial_number(snum)
	cert.set_notBefore(START)
	cert.set_notAfter(END)
	cert.set_issuer(CACert.get_subject())
	cert.set_subject(certreq.get_subject())
	cert.set_pubkey(certreq.get_pubkey())
	cert.set_version(3)

	set_cert_extensions(cert, CACert, isCA=isCA, isRoot=False)
	cert.sign(CAkey, sign_alg)

	return cert, certkey


def create_root_ca(CN, START, END,
				   C='ca', ST='Ontario', L='Toronto',
				   O='Libreswan', OU='Test Department',
				   emailAddress='testing@libreswan.org',
				   ty=crypto.TYPE_RSA, keybits=1024,
				   sign_alg='sha1'):
	""" Create a root CA - Returns the cert, key tuple
	"""
	cakey = create_keypair(ty, keybits)
	careq = create_csr(cakey, CN, C, ST, L, O, OU,
					   emailAddress, sign_alg)

	cacert = crypto.X509()
	cacert.set_serial_number(0)
	cacert.set_notBefore(START)
	cacert.set_notAfter(END)
	cacert.set_issuer(careq.get_subject())
	cacert.set_subject(careq.get_subject())
	cacert.set_pubkey(careq.get_pubkey())
	cacert.set_version(3)

	set_cert_extensions(cacert, cacert,
						isCA=True, isRoot=True)
	cacert.sign(cakey, sign_alg)

	return cacert, cakey


def gmc(timestamp):
	return time.strftime("%Y%m%d%H%M%SZ",
						 time.gmtime(timestamp))


def gen_gmtime_dates():
	""" Generate the dates used for this run.
	Creating openssl gmtime dates may be simpler than this.
	"""
	gmtfmt = "%b %d %H:%M:%S %Y GMT"

	ok_stamp = ssl.cert_time_to_seconds(
			time.strftime(gmtfmt, time.gmtime())) - (60*60*24)
	two_days_ago_stamp = ok_stamp - (60*60*48)
	two_days_ago_end_stamp = two_days_ago_stamp + (60*60*24)
	future_stamp = ok_stamp + (60*60*24*365*1)
	future_end_stamp = future_stamp + (60*60*24*365*1)

	return dict(OK_NOW=gmc(ok_stamp),
				OLD=gmc(two_days_ago_stamp),
				OLD_END=gmc(two_days_ago_end_stamp),
			    FUTURE=gmc(future_stamp),
				FUTURE_END=gmc(future_end_stamp))


def store_cert_and_key(name, cert, key):
	""" Places a ca or end cert and key in the script's global store
	"""
	global ca_certs
	global end_certs

	ext = cert.get_extension(0)
	if ext.get_short_name() == 'basicConstraints':
		# compare the bytes for CA:True
		if '0\x03\x01\x01\xff' == ext.get_data():
			ca_certs[name] = cert, key
		else:
			end_certs[name] = cert, key


def writeout_cert_and_key(certdir, name, cert, privkey):
	""" Write the cert and key files
	"""
	writeout_cert(certdir + name + ".crt", cert)
	writeout_privkey("keys/" + name + ".key", privkey)


def create_basic_pluto_cas(ca_names):
	""" Create the core root certs
	"""
	print "creating CA certs"
	for name in ca_names:
		print " - creating %s" % name
		ca, key = create_root_ca(CN="Libreswan test CA for " + name,
								 START=dates['OK_NOW'],
								 END=dates['FUTURE'])
		writeout_cert_and_key("cacerts/", name, ca, key)
		store_cert_and_key(name, ca, key)


def create_pkcs12(name, cert, key, ca_cert):
	""" Package and write out a .p12 file
	"""
	p12 = crypto.PKCS12()
	p12.set_certificate(cert)
	p12.set_privatekey(key)
	p12.set_friendlyname(name)
	p12.set_ca_certificates([ca_cert])
	with open("pkcs12/" + name + ".p12", "wb") as f:
		f.write(p12.export(passphrase="foobar"))


def create_mainca_end_certs(mainca_end_certs):
	""" Create the core set of end certs from mainca
	"""
	serial = 2
	print "creating mainca's end certs"
	for name in mainca_end_certs:
		# put special cert handling here
		print " - creating %s" % name
		if name == 'bigkey':
			keysize = 2048
		else:
			keysize = 1024

		if name == 'notyetvalid':
			startdate = dates['FUTURE']
			enddate = dates['FUTURE_END']
		elif name == 'notvalidanymore':
			startdate = dates['OLD']
			enddate = dates['OLD_END']
		else:
			startdate = dates['OK_NOW']
			enddate = dates['FUTURE']

		if name == 'signedbyother':
			signer = 'otherca'
		else:
			signer = 'mainca'

		if name == 'wrongdnorg':
			org = "No Such Agency"
		else:
			org = "Libreswan"

		if name == 'unwisechar':
			common_name = 'unwisechar ~!@#$%^&*()-'\
						  '_=+;:/?<>.testing.libreswan.org'
		elif name == 'spaceincn':
			common_name = 'space invaders.testing.libreswan.org'
		elif name == 'cnofca':
			common_name = 'Libreswan test CA for mainca'
		else:
			common_name = name + '.testing.libreswan.org'

		if name == 'hashsha2':
			alg = 'sha256'
		else:
			alg = 'sha1'

		cert, key = create_sub_cert(common_name,
									ca_certs[signer][0],
									ca_certs[signer][1],
									serial, O=org,
									START=startdate, END=enddate,
									keybits=keysize,
									sign_alg=alg)
		writeout_cert_and_key("certs/", name, cert, key)
		store_cert_and_key(name, cert, key)
		create_pkcs12(name, cert, key, ca_certs[signer][0])
		serial += 1


def create_chained_certs(chain_ca_roots):
	""" Create the EE->IA1->IA2->IAx-->CA chains.
	Last in the chain is the end cert
	TODO: Add more complex trust chain situations
	"""
	max_path = 4
	min_path = 1

	for chainca in chain_ca_roots:
		serial = 2
		signpair = ()
		print "creating %s chain" % chainca
		for level in range(min_path, max_path):
			cname = chainca[:-len("root")] + 'intermediate_' + str(level)

			if level == min_path:
				signpair = ca_certs[chainca]

			print " - creating %s" % cname
			ca, key = create_sub_cert(cname + '.testing.libreswan.org',
									  signpair[0], signpair[1], serial,
									  START=dates['OK_NOW'],
									  END=dates['FUTURE'],
									  isCA=True)

			writeout_cert_and_key("certs/", cname, ca, key)
			store_cert_and_key(cname, ca, key)
			signpair = ca_certs[cname]
			level += 1
			serial += 1

			if level >= max_path:
				endcert_name = chainca[:-len("root")] + "endcert"
				print " - creating %s" % endcert_name
				ecert, ekey = create_sub_cert(endcert_name + ".testing.libreswan.org",
											  signpair[0], signpair[1], serial,
											  START=dates['OK_NOW'],
											  END=dates['FUTURE'])

				writeout_cert_and_key("certs/", endcert_name, ecert, ekey)
				store_cert_and_key(endcert_name, ecert, ekey)
				create_pkcs12(endcert_name, ecert, ekey, signpair[0])


def create_leading_zero_crl():
	""" Create our special crl with a signature that starts out with '00:'
	This signs a CRL and checks for a '00' beginning. Each try increments
	the days parameter to result in a different signature
	"""
	zerosig = crypto.CRL()
	signcert, signkey = ca_certs['mainca']
	days = 1

	print "creating a CRL with a leading zero byte signature.."
	while True:
		good = False
		nl = ''

		crl = zerosig.export(signcert, signkey,
							 type=crypto.FILETYPE_TEXT, days=days)
		pem = zerosig.export(signcert, signkey,
							 type=crypto.FILETYPE_PEM, days=days)

		for index, line in enumerate(crl.splitlines()):
			if "Signature Algorithm" in line and index >= 5:
				nl = crl.splitlines()[index + 1].strip()
				if nl.startswith('00'):
					good = True
					break

		if good:
			print nl
			print "found after %d signatures!" % (days)
			with open("crls/crl-leading-zero-byte.pem", "wb") as f:
				f.write(pem)
			break

		days += 1


def create_crlsets():
	""" Create test CRLs
	"""
	print "creating crl set"
	revoked = crypto.Revoked()
	revoked.set_rev_date(dates['OK_NOW'])
	revoked.set_serial(
			str(end_certs['revoked'][0].get_serial_number()))

	future_revoked = crypto.Revoked()
	future_revoked.set_rev_date(dates['FUTURE'])
	future_revoked.set_serial(
			str(end_certs['revoked'][0].get_serial_number()))

	validcrl = crypto.CRL()
	validcrl.add_revoked(revoked)
	with open("crls/cacrlvalid.pem", "wb") as f:
		f.write(validcrl.export(ca_certs['mainca'][0],
								ca_certs['mainca'][1],
								days=15))

	othercrl = crypto.CRL()
	othercrl.add_revoked(revoked)
	with open("crls/othercacrl.pem", "wb") as f:
		f.write(othercrl.export(ca_certs['otherca'][0],
								ca_certs['otherca'][1],
								days=15))

	needupdate = crypto.CRL()
	needupdate.add_revoked(revoked)
	with open("crls/needupdate.pem", "wb") as f:
		f.write(needupdate.export(ca_certs['mainca'][0],
								  ca_certs['mainca'][1],
								  days=0))
	notyet = crypto.CRL()
	notyet.add_revoked(future_revoked)
	with open("crls/futurerevoke.pem", "wb") as f:
		f.write(notyet.export(ca_certs['mainca'][0],
							  ca_certs['mainca'][1],
							  days=15))

	create_leading_zero_crl()


def create_ec_certs():
	""" The OpenSSL module doesn't appear to have
	support for curves so we do it with pexpect
	"""
	print "creating EC certs"
	#create CA
	pexpect.run('openssl ecparam -out keys/curveca.key '
				'-name secp384r1 -genkey -noout')
	child = pexpect.spawn('openssl req -x509 '
						  '-new -key keys/curveca.key '
						  '-out cacerts/curveca.crt '
						  '-days 3650 -set_serial 1')
	child.expect('Country Name')
	child.sendline('ca')
	child.expect('State')
	child.sendline('Ontario')
	child.expect('Locality')
	child.sendline('Toronto')
	child.expect('Organization')
	child.sendline('Libreswan')
	child.expect('Organizational')
	child.sendline('Test Department')
	child.expect('Common')
	child.sendline('Libreswan test EC CA')
	child.expect('Email')
	child.sendline('testing@libreswan.org')
	child.expect(pexpect.EOF)

	serial = 2
	for name in ['east', 'west', 'north', 'road']:
		print "- creating %s-ec" % name
		#create end certs
		pexpect.run('openssl ecparam -out keys/' + name +
					'-ec.key -name secp384r1 -genkey -noout')
		child = pexpect.spawn('openssl req -x509 '
							  '-new -key keys/curveca.key '
							  '-out certs/' + name +
							  '-ec.crt -days 365 -set_serial ' +
							  str(serial))
		child.expect('Country Name')
		child.sendline('ca')
		child.expect('State')
		child.sendline('Ontario')
		child.expect('Locality')
		child.sendline('Toronto')
		child.expect('Organization')
		child.sendline('Libreswan')
		child.expect('Organizational')
		child.sendline('Test Department')
		child.expect('Common')
		child.sendline(name + '-ec.testing.libreswan.org')
		child.expect('Email')
		child.sendline('testing@libreswan.org')
		child.expect(pexpect.EOF)
		serial += 1
		#package p12
		pexpect.run('openssl pkcs12 -export '
					'-inkey keys/%s-ec.key '
				    '-in certs/%s-ec.crt -name %s-ec '
					'-certfile cacerts/curveca.crt '
					'-caname "curveca" '
					'-out pkcs12/curveca/%s-ec.p12 '
					'-passin pass:foobar -passout pass:foobar'
					% (name, name, name, name))


def run_dist_certs():
	""" Generate the pluto test harness x509
	certificates, p12 files, keys, and CRLs
	"""
	# Add root CAs here
	basic_pluto_cas =  ('mainca', 'otherca',
						'east_chain_root', 'west_chain_root')
	# Add end certs here
	mainca_end_certs = ('east','west','sunset',
						'sunrise','north','south',
						'pole','park','beet','carrot',
						'nic','japan','bigkey',
						'notyetvalid','notvalidanymore',
						'signedbyother','wrongdnorg',
						'unwisechar','spaceincn','hashsha2',
						'cnofca','revoked')
	# Add chain roots here
	chain_ca_roots =   ('east_chain_root', 'west_chain_root')

	# Put special case code for new certs in the following functions
	create_basic_pluto_cas(basic_pluto_cas)
	create_chained_certs(chain_ca_roots)
	create_mainca_end_certs(mainca_end_certs)
	create_crlsets()
	create_ec_certs()


def main():
	global dates
	reset_files()
	dates = gen_gmtime_dates()
	print "format dates being used for this run:"
	# TODO: print the display GMT times
	for n, s in dates.iteritems():
		print "%s : %s" % (n, s)

	run_dist_certs()
	print "finished!"


if __name__ == "__main__":
	main()
