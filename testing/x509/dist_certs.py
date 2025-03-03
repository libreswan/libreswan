#!/usr/bin/python3
""" dist_certs.py: create a suite of x509 certificates for the Libreswan
    test harness

 Copyright (C) 2014-2015 Matt Rogers <mrogers@redhat.com>
 Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the
 Free Software Foundation; either version 2 of the License, or (at your
 option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 for more details.

    WARNING! Your PyOpenSSL needs a patch from here:
    https://github.com/pyca/pyopenssl/pull/161
    NSS doesn't allow md5 CRL signatures. This patch lets you use
    the CRL export method and specify an acceptable signature type.



 Extended Key Usage

    The certificate MAY include Extended Key Usage extension. The
    criticality of this extension MUST NOT impact verification of the
    certificate, including when the extension includes values that are
    not recognised to the implementation. If the extension is present
    at least one of the following values MUST be present:

 EKU OIDs
    Server Authentication (OID 1.3.6.1.5.5.7.3.1)
    Client Authentication (OID 1.3.6.1.5.5.7.3.2)
    Code Signing (OID 1.3.6.1.5.5.7.3.3)
    Email Protection (OID 1.3.6.1.5.5.7.3.4)
    IPSec End System (OID 1.3.6.1.5.5.7.3.5) - technically deprecated
    IPSec Tunnel (OID 1.3.6.1.5.5.7.3.6) - technically deprecated
    IPSec User (OID 1.3.6.1.5.5.7.3.7) - technically deprecated
    Time Stamping (OID 1.3.6.1.5.5.7.3.8)
    OCSP Signing (OID 1.3.6.1.5.5.7.3.9)
    eapOverPPP (OID 1.3.6.1.5.5.7.3.13)
    eapOverLAN (OID 1.3.6.1.5.5.7.3.14)
    ipsecIKE (OID 1.3.6.1.5.5.7.3.17)
    ikeEnd IPSec End System (OID 1.3.6.1.5.5.8.2.1)
    ikeIntermediate IPSec Intermediate System (OID 1.3.6.1.5.5.8.2.2)
    pkixSSHClient (OID 1.3.6.1.5.5.7.3.21)
    pkixSSHServer (OID 1.3.6.1.5.5.7.3.22)
    Microsoft Server Gated Crypto (OID 1.3.6.1.4.1.311.10.3.3)
    Netscape Server Gated Crypto (OID 2.16.840.1.113730.4.1)
    Any key usage (OID 2.5.29.37.0)

  openssl supported EKU names:
    serverAuth             SSL/TLS Web Server Authentication.
    clientAuth             SSL/TLS Web Client Authentication.
    codeSigning            Code signing.
    emailProtection        E-mail Protection (S/MIME).
    timeStamping           Trusted Timestamping
    OCSPSigning            OCSP Signing
    ipsecIKE               ipsec Internet Key Exchange
    msCodeInd              Microsoft Individual Code Signing (authenticode)
    msCodeCom              Microsoft Commercial Code Signing (authenticode)
    msCTLSign              Microsoft Trust List Signing
    msEFS                  Microsoft Encrypted File System


 Key Usage

    The certificate MAY include Key Usage extension. Key Usage extension
    MUST include either the digitalSignature, nonRepudiation or both
    of those flags. It being set as critical MUST NOT impact
    verification of the certificate. Other flags in the extension MUST
    NOT impact verification of the certificate.

  openssl supported KU names:

    digitalSignature
    nonRepudiation
    keyEncipherment
    dataEncipherment
    keyAgreement
    keyCertSign
    cRLSign
    encipherOnly
    decipherOnly

 """

import os
import sys
import ssl
import shutil
import subprocess
import time
from datetime import datetime, timedelta
from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

CRL_URI = 'URI:http://nic.testing.libreswan.org/revoked.crl'

NOW = ""
FUTURE = ""
FUTURE_END = ""

ca_certs = {}
end_certs = {}
endrev_name = ""
top_caname=""

def reset_files():
    for dir in ['keys/', 'certs/', 'selfsigned/',
                'pkcs12/',
                'pkcs12/mainca']:
        if os.path.isdir(dir):
            shutil.rmtree(dir)
        os.mkdir(dir)

def writeout_cert(filename, cert):
    blob = cert.public_bytes(serialization.Encoding.PEM)
    with open(filename, "wb") as f:
        f.write(blob)


def writeout_privkey(filename, key):
    blob = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())
    with open(filename, "wb") as f:
        f.write(blob)


def writeout_cert_and_key(name, cert, privkey):
    """ Write the cert and key files
    """
    writeout_cert("certs/" + name + ".crt", cert)
    writeout_privkey("keys/" + name + ".key", privkey)
    with open("certs/" + name + ".serial", "w") as f:
        serial = cert.serial_number
        f.write(f"{serial}\n")


def create_csr(key, hash_alg=hashes.SHA256,
               CN=None, C=None, ST=None, L=None, O=None, OU=None,
               emailAddress=None):
    """ Create the certreq
    """
    subjects = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, C),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ST),
        x509.NameAttribute(NameOID.LOCALITY_NAME, L),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, O),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU),
        x509.NameAttribute(NameOID.COMMON_NAME, CN),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, emailAddress),
    ]
    csr = x509.CertificateSigningRequestBuilder() \
              .subject_name(x509.Name(subjects)) \
              .sign(key, hash_alg())
    return csr

def add_ext(cert, kind, crit, string):
    #print("DEBUG: %s"%string)
    cert.add_extensions([crypto.X509Extension(kind.encode('utf-8'), crit, string.encode('utf-8'))])

def set_cert_extensions(cert, isCA=False, ocsp=False, ocspuri=True):
    ocspeku = 'serverAuth,clientAuth,codeSigning,OCSPSigning'
    cnstr = str(cert.get_subject().commonName)


    # Create Basic Constraints
    if isCA:
        bc = "CA:TRUE"
    else:
        bc = "CA:FALSE"

    if 'bcOmit' not in cnstr:
        cf = False
        if 'bcCritical' in cnstr:
            cf = True
        add_ext(cert, 'basicConstraints', False, bc)


    # Create Subject Alt Name (SAN)
    if not isCA and '-nosan' not in cnstr:
        SAN = "DNS: " + cnstr
        if "." in cnstr:
            ee = cnstr.split(".")[0]
            print("EE:%s"% ee)
            if ee == "west" or ee == "east" or ee == "semiroad":
                SAN += ", email:%s@testing.libreswan.org"%ee
                if ee == "west":
                    SAN += ", IP:192.1.2.45, IP:2001:db8:1:2::45"
                if ee == "east":
                    SAN += ", IP:192.1.2.23, IP:2001:db8:1:2::23"
                if ee == "semiroad":
                    SAN += ", IP:192.1.3.209, IP:2001:db8:1:3::209"
        if 'sanCritical' in cnstr:
            add_ext(cert, 'subjectAltName', True, SAN)
        else:
            add_ext(cert, 'subjectAltName', False, SAN)


    # Create Key Usage (KU)
    ku_str = 'digitalSignature'
    if isCA or ocsp:
        ku_str = 'digitalSignature,keyCertSign,cRLSign'

    # check for custom Key Usage
    if '-ku-' in cnstr:
        ku_str = ''
        for ku_entry in ( 'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
                          'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly' ):
            if ku_entry in cnstr:
                ku_str = ku_str + "," + ku_entry
        if 'kuBOGUS' in cnstr:
            ku_str = ku_str + ",1.3.6.1.5.5.42.42.42" # bogus OID
    if 'kuEmpty' in cnstr:
        ku_str = ''
    if '-kuOmit' not in cnstr:
        cf = False
        if 'kuCritical' in cnstr:
            cf = True
        if ku_str != '' and ku_str[0] == ',':
            ku_str = ku_str[1:]
        add_ext(cert, 'keyUsage', cf, ku_str)

    # Create Extended Key Usage (KU)
    eku_str = 'serverAuth,clientAuth' # arbitrary default most often used in the wild
    # check for custom Key Usage
    if '-eku-' in cnstr:
        eku_str = ''
        for eku_entry in ( 'serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping',
                           'OCSPSigning', 'ipsecIKE', 'msCodeInd', 'msCodeCom', 'msCTLSign', 'msEFS' ):
            if eku_entry in cnstr:
                eku_str = eku_str + "," + eku_entry
        # some informal names mapping to non-openssl supported OIDs
        if '-ipsecEndSystem' in cnstr:
            eku_str = eku_str + ",1.3.6.1.5.5.7.3.5"
        if '-ipsecTunnel' in cnstr:
            eku_str = eku_str + ",1.3.6.1.5.5.7.3.6"
        if '-ipsecUser' in cnstr:
            eku_str = eku_str + ",1.3.6.1.5.5.7.3.7"
        if '-ipsecIKE' in cnstr:
            eku_str = eku_str + ",1.3.6.1.5.5.7.3.17"
        if '-iKEIntermediate' in cnstr:
            eku_str = eku_str + ",1.3.6.1.5.5.8.2.2"
        if '-iKEEnd' in cnstr:
            eku_str = eku_str + ",1.3.6.1.5.5.8.2.1"
        if '-ekuBOGUS' in cnstr:
            eku_str = eku_str + ",'1.3.6.1.5.5.42.42.42'" # bogus OID
    if ocsp:
        eku_str = ocspeku
    if 'ekuEmpty' in cnstr:
        eku_str = ''
    if '-ekuOmit' not in cnstr:
        cf = False
        if 'ekuCritical' in cnstr:
            cf = True
        if eku_str != '' and eku_str[0] == ',':
            eku_str = eku_str[1:]
        add_ext(cert, 'extendedKeyUsage', cf, eku_str)


    # Create OCSP
    if ocspuri and '-ocspOmit' not in cnstr:
            add_ext(cert, 'authorityInfoAccess', False,
                  'OCSP;URI:http://nic.testing.libreswan.org:2560')

    # Create CRL DP
    if '-crlOmit' not in cnstr:
        add_ext(cert, 'crlDistributionPoints', False, CRL_URI)

def create_sub_cert(CN, cacert, cakey, snum, START, END,
                    C='CA', ST='Ontario', L='Toronto',
                    O='Libreswan', OU='Test Department',
                    emailAddress='',
                    keysize=2048,
                    isCA=False, ocsp=False):
    """ Create a subordinate cert and return the cert, key tuple
    This could be a CA for an intermediate, or not for an EE
    """

    certkey = rsa.generate_private_key(public_exponent=3, key_size=keysize)
    certreq = create_csr(certkey,
                         CN=CN, C=C, ST=ST, L=L, O=O, OU=OU,
                         emailAddress=emailAddress)

    print(f"START-END: {START}-{END}")

    cert = crypto.X509()
    cert.set_serial_number(snum)
    cert.set_notBefore(START.encode('utf-8'))
    cert.set_notAfter(END.encode('utf-8'))
    cert.set_issuer(crypto.X509.from_cryptography(cacert).get_subject())
    cert.set_subject(crypto.X509Req.from_cryptography(certreq).get_subject())
    cert.set_pubkey(crypto.X509Req.from_cryptography(certreq).get_pubkey())
    cert.set_version(2)

    if CN == 'nic-nourl.testing.libreswan.org':
        ocspuri = False
    else:
        ocspuri = True

    set_cert_extensions(cert, isCA=isCA, ocsp=ocsp, ocspuri=ocspuri)
    cert.sign(crypto.PKey.from_cryptography_key(cakey), hashes.SHA256.name)

    return cert.to_cryptography(), certkey


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
    # Make future certs only +300 days, so we have a time overlap
    # between currently valid certs (1 year) and these futuristic
    # certs
    future_stamp = ok_stamp + (60*60*24*365*1)
    future_end_stamp = future_stamp + (60*60*24*365*2)

    global NOW
    global FUTURE
    global FUTURE_END

    NOW = gmc(ok_stamp)
    FUTURE = gmc(future_stamp)
    FUTURE_END = gmc(future_end_stamp)


def store_cert_and_key(name, cert, key):
    """ Places a ca or end cert and key in the script's global store
    """
    global ca_certs
    global end_certs

    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            ca_certs[name] = cert, key
            return
    except x509.extensions.ExtensionNotFound:
        pass

    end_certs[name] = cert, key

PASSPHRASE = ""	# set below

def load_mainca_cas():
    name = 'mainca'
    p12="real/" + name + "/root.p12"
    print("Loading %s" % (p12))
    with open(p12, "rb") as f:
        blob = f.read()
        key, ca, chain = pkcs12.load_key_and_certificates(blob, PASSPHRASE)
        store_cert_and_key(name, ca, key)

def writeout_pkcs12(path, name, cert, key, ca_cert):
    """ Package and write out a .p12 file
    """
    blob = pkcs12.serialize_key_and_certificates(name.encode('utf-8'),
                                                 key, cert, [ca_cert],
                                                 serialization.BestAvailableEncryption(PASSPHRASE))
    with open(path + name + ".p12", "wb") as f:
        f.write(blob)


def create_mainca_end_certs(mainca_end_certs):
    """ Create the core set of end certs from mainca
    """

    # load the next serial file in the CA's directory
    serial = 0
    with open("real/mainca/serial", "r") as f:
        serial = int(f.read())

    print("creating mainca's end certs")
    for name in mainca_end_certs:
        # put special cert handling here
        print(" - creating %s %d" % (name, serial))
        keysize = 3072
        if name == 'key2032':
            keysize = 2032
        if name == 'key4096':
            keysize = 4096

        startdate = NOW
        enddate = FUTURE_END

        signer = 'mainca'

        if name == 'nic':
            ocsp_resp = True
        else:
            ocsp_resp = False

        org = "Libreswan"

        common_name = name + '.testing.libreswan.org'

        if " " in common_name:
            emailAddress = "root@testing.libreswan.org"
        else:
            emailAddress = "user-%s@testing.libreswan.org"%name

        #print("CA signer is %s"%signer)
        #print(ca_certs)
        #print(end_certs)
        cert, key = create_sub_cert(common_name,
                                    ca_certs[signer][0],
                                    ca_certs[signer][1],
                                    serial, O=org,
                                    emailAddress=emailAddress,
                                    START=startdate, END=enddate,
                                    keysize=keysize,
                                    ocsp=ocsp_resp)
        writeout_cert_and_key(name, cert, key)
        store_cert_and_key(name, cert, key)
        cmd = (f"openssl pkcs12" +
	       f" -export" +
	       f" -passout pass:foobar" +
	       f" -in certs/{name}.crt" +
	       f" -inkey keys/{name}.key" +
	       f" -name {name}" +
	       f" -out pkcs12/{signer}/{name}.p12" +
               f" -certfile real/mainca/root.cert" +
               f"")
        print(cmd, subprocess.getoutput(cmd))

        serial += 1

    # update the next serial file in the CA's directory
    with open("real/mainca/serial", "w") as f:
        f.write(f"{serial}\n")


def main():
    outdir = os.path.dirname(sys.argv[0])
    cwd = os.getcwd()
    if outdir:
        os.chdir(outdir)
    global dates
    reset_files()

    gen_gmtime_dates()

    print("format dates being used for this run:")
    print(f"NOW : {NOW}")
    print(f"FUTURE : {FUTURE}")
    print(f"FUTURE_END : {FUTURE_END}")

    print("reading passphrase")
    global PASSPHRASE
    with open("nss-pw", "rb") as f:
        PASSPHRASE = f.read()
    print("passphrase: ", PASSPHRASE)


    # Add end certs here
    mainca_end_certs = ('west-kuOmit', # Key Usage should not be needed
                        'west-eku-clientAuth', # should be enough to validate
                        'west-eku-serverAuth', # should be enough to validate
                        'west-bcOmit', # Basic Constraints should not be needed
                        'west-ekuOmit', # Extended Key Usage should not be needed
                        'west-nosan', 'east-nosan', # No Subject Alt Names
                        'west-sanCritical', # should work
                        'west-bcCritical', # Basic Constraints critical flag should be ignored
                        'west-kuCritical', # Key Usage critical flag should be ignored
                        'west-ekuCritical', # Extended Key Usage critical flag should be ignored ??
                        'west-ku-keyAgreement-digitalSignature', # Should work
                        'west-ku-nonRepudiation', # Should work
                        'west-ekuBOGUS-bad', # Should fail because it needs a recognised EKU
                        'west-eku-ipsecIKE', # Should work
                        'west-ekuCritical-eku-ipsecIKE', # Should still work
                        'west-ekuCritical-eku-emailProtection', # Should still work
                        'nic-nourl',
                        'key2032', 'key4096',
                        'semiroad')

    # Put special case code for new certs in the following functions
    load_mainca_cas()
    create_mainca_end_certs(mainca_end_certs)

    print("finished!")

if __name__ == "__main__":
    main()
