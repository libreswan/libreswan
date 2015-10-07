#!/usr/bin/python
""" dist_certs.py: create a suite of x509 certificates for the Libreswan
	test harness

 Copyright (C) 2014-2015 Matt Rogers <mrogers@redhat.com>
 Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the
 Free Software Foundation; either version 2 of the License, or (at your
 option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 for more details.

	WARNING! Your PyOpenSSL needs a patch from here:
	https://github.com/pyca/pyopenssl/pull/161
	NSS doesn't allow md5 CRL signatures. This patch lets you use
	the CRL export method and specify an acceptable signature type.

 """

import os
import sys
import ssl
import shutil
import subprocess
import time
from datetime import datetime, timedelta
import pexpect
from OpenSSL import crypto

CRL_URI = 'URI:http://nic.testing.libreswan.org/revoked.crl'

dates = {}
ca_certs = {}
end_certs = {}
endrev_name = ""
top_caname=""

def reset_files():
	for dir in ['keys/', 'cacerts/', 'certs/', 'pkcs12/',
			    'pkcs12/curveca', 'pkcs12/mainca',
				'pkcs12/otherca', 'crls/']:
		if os.path.isdir(dir):
			shutil.rmtree(dir)
		os.mkdir(dir)
	for file in ['nss-pw']:
		if os.path.isfile(file):
			os.remove(file)

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

def add_ext(cert, kind, crit, string):
	cert.add_extensions([crypto.X509Extension(kind, crit, string)])

def set_cert_extensions(cert, issuer, isCA=False, isRoot=False, ocsp=False, ocspuri=True):
	ku_str = 'digitalSignature'
	eku_str = ''
	ocspeku = 'serverAuth,clientAuth,codeSigning,OCSPSigning'
	cnstr = str(cert.get_subject().commonName)

	if isCA:
		ku_str = ku_str + ',keyCertSign,cRLSign'
		bc = "CA:TRUE"
	else:
		bc = "CA:FALSE"

	add_ext(cert, 'basicConstraints', False, bc)

	if not isCA:
		dnsname = "DNS: " + cnstr
		add_ext(cert, 'subjectAltName', False, dnsname)

	if cnstr == 'usage-server.testing.libreswan.org':
		eku_str = 'serverAuth'
		ku_str = ku_str + ',keyEncipherment'
	elif cnstr == 'usage-client.testing.libreswan.org':
		eku_str = 'clientAuth'
		ku_str = ku_str + ',nonRepudiation'
	elif cnstr == 'usage-both.testing.libreswan.org':
		eku_str = 'serverAuth,clientAuth'
		ku_str = ku_str + ',keyEncipherment,nonRepudiation'

	if ocsp:
		ku_str = ku_str + ',keyCertSign,cRLSign'
		eku_str = ocspeku

	add_ext(cert, 'keyUsage', False, ku_str)
	if eku_str is not '':
		add_ext(cert, 'extendedKeyUsage', False, eku_str)

	if ocspuri:
		add_ext(cert, 'authorityInfoAccess', False,
		  		'OCSP;URI:http://nic.testing.libreswan.org:2560')

	add_ext(cert, 'crlDistributionPoints', False, CRL_URI)

def create_sub_cert(CN, CACert, CAkey, snum, START, END,
					C='CA', ST='Ontario', L='Toronto',
					O='Libreswan', OU='Test Department',
					emailAddress='testing@libreswan.org',
					ty=crypto.TYPE_RSA, keybits=1024,
					sign_alg='sha1', isCA=False, ocsp=False):
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
	cert.set_version(2)

	if CN == 'nic-nourl.testing.libreswan.org':
		ocspuri = False
	else:
		ocspuri = True

	set_cert_extensions(cert, CACert, isCA=isCA, isRoot=False, ocsp=ocsp,
															   ocspuri=ocspuri)
	cert.sign(CAkey, sign_alg)

	return cert, certkey


def create_root_ca(CN, START, END,
				   C='CA', ST='Ontario', L='Toronto',
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
	cacert.set_version(2)

	set_cert_extensions(cacert, cacert,
						isCA=True, isRoot=True, ocsp=True, ocspuri=True)
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


def create_pkcs12(path, name, cert, key, ca_cert):
	""" Package and write out a .p12 file
	"""
	p12 = crypto.PKCS12()
	p12.set_certificate(cert)
	p12.set_privatekey(key)
	p12.set_friendlyname(name)
	p12.set_ca_certificates([ca_cert])
	with open(path + name + ".p12", "wb") as f:
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
			if name == 'key4096':
				keysize = 4096
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

		if name == 'nic':
			ocsp_resp = True
		else:
			ocsp_resp = False

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
									sign_alg=alg, ocsp=ocsp_resp)
		writeout_cert_and_key("certs/", name, cert, key)
		store_cert_and_key(name, cert, key)
		create_pkcs12("pkcs12/"+ signer + '/',
					  name, cert, key, ca_certs[signer][0])
		serial += 1


def create_chained_certs(chain_ca_roots, max_path, prefix=''):
	""" Create the EE->IA1->IA2->IAx-->CA chains.
	Last in the chain is the end cert
	TODO: Add more complex trust chain situations
	"""
	global endrev_name
	global top_caname
	min_path = 1
	ca_cnt = 0

	for chainca in chain_ca_roots:
		serial = len(end_certs) + ca_cnt
		lastca = ""
		#note there's an issue with the authkeyid in the chain
		#signpair = ()
		print "creating %s chain" % chainca
		for level in range(min_path, max_path):
			cname = prefix + chainca + '_int_' + str(level)

			print "level %d cname %s serial %d" % (level, cname, serial)

			if level == min_path:
				lastca = "mainca"

			signpair = ca_certs[lastca]
			print " - creating %s with the last ca of %s" % (cname, lastca)
			ca, key = create_sub_cert(cname + '.testing.libreswan.org',
									  signpair[0], signpair[1], serial,
									  START=dates['OK_NOW'],
									  END=dates['FUTURE'],
									  isCA=True, ocsp=False)

			writeout_cert_and_key("certs/", cname, ca, key)
			store_cert_and_key(cname, ca, key)
			lastca = cname
			serial += 1
			ca_cnt += 1

			if level == max_path - 1:
				endcert_name = prefix + chainca + "_endcert"
				
				signpair = ca_certs[lastca]
				print " - creating %s" % endcert_name
				ecert, ekey = create_sub_cert(endcert_name + ".testing.libreswan.org",
											  signpair[0], signpair[1], serial,
											  START=dates['OK_NOW'],
											  END=dates['FUTURE'])

				writeout_cert_and_key("certs/", endcert_name, ecert, ekey)
				store_cert_and_key(endcert_name, ecert, ekey)
				create_pkcs12("pkcs12/", endcert_name, ecert, ekey, signpair[0])
				serial += 1

				endrev_name = prefix + chainca + "_revoked"
				top_caname = cname
				print " - creating %s" % endrev_name
				ercert, erkey = create_sub_cert(endrev_name + ".testing.libreswan.org",
											  signpair[0], signpair[1], serial,
											  START=dates['OK_NOW'],
											  END=dates['FUTURE'])

				writeout_cert_and_key("certs/", endrev_name, ercert, erkey)
				store_cert_and_key(endrev_name, ercert, erkey)
				create_pkcs12("pkcs12/", endrev_name, ercert, erkey, signpair[0])

# this special crl was for a openswan/nss freebl combo bug, both of which should
# long be done with.

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
							 type=crypto.FILETYPE_TEXT, days=days, digest='sha1')
		der = zerosig.export(signcert, signkey,
							 type=crypto.FILETYPE_ASN1, days=days, digest='sha1')

		for index, line in enumerate(crl.splitlines()):
			if "Signature Algorithm" in line and index >= 5:
				nl = crl.splitlines()[index + 1].strip()
				if nl.startswith('00'):
					good = True
					break

		if good:
			print nl
			print "found after %d signatures!" % (days)
			with open("crls/crl-leading-zero-byte.crl", "wb") as f:
				f.write(der)
			break

		days += 1


def create_crlsets():
	""" Create test CRLs
	"""
	print "creating crl set"
	revoked = crypto.Revoked()
	chainrev = crypto.Revoked()
	future_revoked = crypto.Revoked()

	revoked.set_rev_date(dates['OK_NOW'])
	chainrev.set_rev_date(dates['OK_NOW'])
	future_revoked.set_rev_date(dates['FUTURE'])
	# the get_serial_number method results in a hex str like '0x17'
	# but set_serial needs a hex str like '17'
	revoked.set_serial(
			hex(end_certs['revoked'][0].get_serial_number())[2:])

	chainrev.set_serial(
			hex(end_certs['west_chain_revoked'][0].get_serial_number())[2:])

	future_revoked.set_serial(
			hex(end_certs['revoked'][0].get_serial_number())[2:])

	needupdate = crypto.CRL()
	needupdate.add_revoked(revoked)
	needupdate.add_revoked(chainrev)
	with open("crls/needupdate.crl", "wb") as f:
		f.write(needupdate.export(ca_certs['mainca'][0],
								  ca_certs['mainca'][1],
								  type=crypto.FILETYPE_ASN1,
								  days=0, digest='sha1'))

	print "sleeping for needupdate/valid crl time difference"
	time.sleep(5)
	validcrl = crypto.CRL()
	validcrl.add_revoked(revoked)
	validcrl.add_revoked(chainrev)
	with open("crls/cacrlvalid.crl", "wb") as f:
		f.write(validcrl.export(ca_certs['mainca'][0],
								ca_certs['mainca'][1],
								type=crypto.FILETYPE_ASN1,
								days=15, digest='sha1'))

	othercrl = crypto.CRL()
	othercrl.add_revoked(revoked)
	othercrl.add_revoked(chainrev)
	with open("crls/othercacrl.crl", "wb") as f:
		f.write(othercrl.export(ca_certs['otherca'][0],
								ca_certs['otherca'][1],
								type=crypto.FILETYPE_ASN1,
								days=15, digest='sha1'))

	notyet = crypto.CRL()
	notyet.add_revoked(future_revoked)
	with open("crls/futurerevoke.crl", "wb") as f:
		f.write(notyet.export(ca_certs['mainca'][0],
							  ca_certs['mainca'][1],
							  type=crypto.FILETYPE_ASN1,
							  days=15, digest='sha1'))

	 #create_leading_zero_crl()


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
	child.sendline('CA')
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
		child.sendline('CA')
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
	basic_pluto_cas =  ('mainca', 'otherca')
	# Add end certs here
	mainca_end_certs = ('nic','east','west', 'road', 'sunset',
						'sunrise','north','south',
						'pole','park','beet','carrot',
					    'usage-server', 'usage-client',
					    'usage-both',
						'nic-noext', 'nic-nourl',
						'japan','bigkey', 'key4096',
						'notyetvalid','notvalidanymore',
						'signedbyother','wrongdnorg',
						'unwisechar','spaceincn','hashsha2',
						'cnofca','revoked')
	# Add chain roots here
	chain_ca_roots =   ('east_chain', 'west_chain')

	# Put special case code for new certs in the following functions
	create_basic_pluto_cas(basic_pluto_cas)
	create_mainca_end_certs(mainca_end_certs)
	create_chained_certs(chain_ca_roots, 3)
	create_chained_certs(chain_ca_roots, 9, 'long_')
	create_chained_certs(chain_ca_roots, 10, 'too_long_')
	create_crlsets()
	create_ec_certs()

def create_nss_pw():
	print "creating nss-pw"
	f = open("nss-pw","w")
	f.write("foobar")
	f.close()

def main():
	outdir = os.path.dirname(sys.argv[0])
	cwd = os.getcwd()
	os.chdir(outdir)
	global dates
	reset_files()
	dates = gen_gmtime_dates()
	print "format dates being used for this run:"
	# TODO: print the display GMT times
	for n, s in dates.iteritems():
		print "%s : %s" % (n, s)

	run_dist_certs()

	create_nss_pw()
	os.chdir(cwd)
	print "finished!"


if __name__ == "__main__":
	main()
