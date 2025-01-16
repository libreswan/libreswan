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
import pexpect
from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

CRL_URI = 'URI:http://nic.testing.libreswan.org/revoked.crl'

valid_ku_list = ( 'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly' )

valid_eku_list = ( 'serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'OCSPSigning', 'ipsecIKE', 'msCodeInd', 'msCodeCom', 'msCTLSign', 'msEFS' )

dates = {}
ca_certs = {}
end_certs = {}
endrev_name = ""
top_caname=""
dirbase=""

def reset_files():
    for dir in ['keys/', 'cacerts/', 'certs/', 'selfsigned/',
                'pkcs12/',
                'pkcs12/curveca',
                'pkcs12/mainca',
                'pkcs12/otherca',
                'pkcs12/badca',
                'crls/' ]:
        if os.path.isdir(dir):
            shutil.rmtree(dir)
        os.mkdir(dir)
    for file in ['nss-pw']:
        if os.path.isfile(file):
            os.remove(file)

def run(command, events=None, logfile=None):
    # logfile=sys.stdout.buffer
    print("", command)
    output, status = pexpect.run(command, withexitstatus=True, events=events,
                                 logfile=logfile,
                                 cwd=dirbase and dirbase or ".")
    if status:
        print("")
        print(output)
        print("")
        throw

def writeout_cert(filename, cert):
    global dirbase
    blob = cert.public_bytes(serialization.Encoding.PEM)
    with open(dirbase + filename, "wb") as f:
        f.write(blob)


def writeout_privkey(filename, key):
    global dirbase
    blob = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())
    with open(dirbase + filename, "wb") as f:
        f.write(blob)


def writeout_cert_and_key(certdir, name, cert, privkey):
    """ Write the cert and key files
    """
    writeout_cert(certdir + name + ".crt", cert)
    writeout_privkey("keys/" + name + ".key", privkey)


def create_keypair(algo=crypto.TYPE_RSA, bits=2048):
    """ Create an OpenSSL keypair
    """
    pkey = crypto.PKey()
    pkey.generate_key(algo, bits)
    return pkey


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

def set_cert_extensions(cert, issuer, isCA=False, isRoot=False, ocsp=False, ocspuri=True):
    ocspeku = 'serverAuth,clientAuth,codeSigning,OCSPSigning'
    cnstr = str(cert.get_subject().commonName)


    # Create Basic Constraints
    if isCA:
        if "badca" in str(issuer.get_subject().commonName):
            bc = "CA:FALSE"
        else:
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
            if ee == "otherwest" or ee == "othereast":
                SAN += ", email:%s@other.libreswan.org"%ee
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
        for ku_entry in valid_ku_list:
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
        for eku_entry in valid_eku_list:
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
                    keypair=lambda: rsa.generate_private_key(public_exponent=3, key_size=2048),
                    sign_alg=hashes.SHA256, isCA=False, ocsp=False):
    """ Create a subordinate cert and return the cert, key tuple
    This could be a CA for an intermediate, or not for an EE
    """

    certkey = keypair()
    certreq = create_csr(certkey,
                         CN=CN, C=C, ST=ST, L=L, O=O, OU=OU,
                         emailAddress=emailAddress)

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

    set_cert_extensions(cert, crypto.X509.from_cryptography(cacert),
                        isCA=isCA, isRoot=False, ocsp=ocsp, ocspuri=ocspuri)
    cert.sign(crypto.PKey.from_cryptography_key(cakey), sign_alg.name)

    return cert.to_cryptography(), certkey


def create_root_ca(CN, START, END,
                   C='CA', ST='Ontario', L='Toronto',
                   O='Libreswan', OU='Test Department',
                   emailAddress='testing@libreswan.org',
                   keypair=lambda: rsa.generate_private_key(public_exponent=3, key_size=2048),
                   ty=crypto.TYPE_RSA, keybits=2048,
                   sign_alg=hashes.SHA256):
    """ Create a root CA - Returns the cert, key tuple
    """
    cakey = keypair()
    careq = create_csr(cakey, CN=CN, C=C, ST=ST, L=L, O=O, OU=OU,
                       emailAddress=emailAddress)

    cacert = crypto.X509()
    cacert.set_serial_number(0)
    cacert.set_notBefore(START.encode('utf-8'))
    cacert.set_notAfter(END.encode('utf-8'))
    cacert.set_issuer(crypto.X509Req.from_cryptography(careq).get_subject())
    cacert.set_subject(crypto.X509Req.from_cryptography(careq).get_subject())
    cacert.set_pubkey(crypto.X509Req.from_cryptography(careq).get_pubkey())
    cacert.set_version(2)

    set_cert_extensions(cacert, cacert, isCA=True, isRoot=True, ocsp=True, ocspuri=True)
    cacert.sign(crypto.PKey.from_cryptography_key(cakey), sign_alg.name)

    return cacert.to_cryptography(), cakey


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

    return dict(OK_NOW=gmc(ok_stamp),
                FUTURE=gmc(future_stamp),
                FUTURE_END=gmc(future_end_stamp))


def store_cert_and_key(name, cert, key):
    """ Places a ca or end cert and key in the script's global store
    """
    global ca_certs
    global end_certs

    if name == "badca":
        ca_certs[name] = cert, key
        return

    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            ca_certs[name] = cert, key
            return
    except x509.extensions.ExtensionNotFound:
        pass

    end_certs[name] = cert, key


def create_basic_pluto_cas(ca_names):
    """ Create the core root certs
    """
    print("creating CA certs")
    for name in ca_names:
        print(" - creating %s"% name)
        ca, key = create_root_ca(CN="Libreswan test CA for " + name,
                                 START=dates['OK_NOW'],
                                 END=dates['FUTURE_END'])
        writeout_cert_and_key("cacerts/", name, ca, key)
        store_cert_and_key(name, ca, key)


def writeout_pkcs12(path, name, cert, key, ca_cert):
    """ Package and write out a .p12 file
    """
    blob = pkcs12.serialize_key_and_certificates(name.encode('utf-8'),
                                                 key, cert, [ca_cert],
                                                 serialization.BestAvailableEncryption(b"foobar"))
    with open(dirbase + path + name + ".p12", "wb") as f:
        f.write(blob)


def create_mainca_end_certs(mainca_end_certs):
    """ Create the core set of end certs from mainca
    """
    serial = 2
    print("creating mainca's end certs")
    for name in mainca_end_certs:
        # put special cert handling here
        print(" - creating %s"% name)
        keysize = 3072
        if name == 'smallkey':
            keysize = 1024
        if name == 'mediumkey':
            keysize = 2048
        if name == 'key2032':
            keysize = 2032
        if name == 'key4096':
            keysize = 4096

        startdate = dates['OK_NOW']
        enddate = dates['FUTURE_END']

        if 'other' in name:
            signer = 'otherca'
        elif name[:3] == 'bad':
            signer = 'badca'
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
        elif 'other' in name:
            common_name = name + '.other.libreswan.org'
        else:
            common_name = name + '.testing.libreswan.org'

        if name == 'hashsha1':
            sign_alg = hashes.SHA1
        else:
            sign_alg = hashes.SHA256

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
                                    keypair=lambda: rsa.generate_private_key(public_exponent=3, key_size=keysize),
                                    sign_alg=sign_alg, ocsp=ocsp_resp)
        writeout_cert_and_key("certs/", name, cert, key)
        store_cert_and_key(name, cert, key)
        writeout_pkcs12("pkcs12/"+ signer + '/', name,
                        cert, key, ca_certs[signer][0])
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
        print("creating %s chain"% chainca)
        for level in range(min_path, max_path):
            cname = prefix + chainca + '_int_' + str(level)

            print("level %d cname %s serial %d"% (level, cname, serial))

            if level == min_path:
                lastca = "mainca"

            signpair = ca_certs[lastca]
            print(" - creating %s with the last ca of %s"% (cname, lastca))
            ca, key = create_sub_cert(cname + '.testing.libreswan.org',
                                      signpair[0], signpair[1], serial,
                                      START=dates['OK_NOW'],
                                      END=dates['FUTURE'],
                                      emailAddress="%s@testing.libreswan.org"%cname,
                                      isCA=True, ocsp=False)

            writeout_cert_and_key("certs/", cname, ca, key)
            store_cert_and_key(cname, ca, key)
            lastca = cname
            serial += 1
            ca_cnt += 1

            if level == max_path - 1:
                endcert_name = prefix + chainca + "_endcert"

                signpair = ca_certs[lastca]
                print(" - creating %s"% endcert_name)
                ecert, ekey = create_sub_cert(endcert_name + ".testing.libreswan.org",
                                              signpair[0], signpair[1], serial,
                                              emailAddress="%s@testing.libreswan.org"%endcert_name,
                                              START=dates['OK_NOW'],
                                              END=dates['FUTURE'])

                writeout_cert_and_key("certs/", endcert_name, ecert, ekey)
                store_cert_and_key(endcert_name, ecert, ekey)
                writeout_pkcs12("pkcs12/", endcert_name,
                                ecert, ekey, signpair[0])
                serial += 1

                endrev_name = prefix + chainca + "_revoked"
                top_caname = cname
                print(" - creating %s"% endrev_name)
                ercert, erkey = create_sub_cert(endrev_name + ".testing.libreswan.org",
                                              signpair[0], signpair[1], serial,
                                              emailAddress="%s@testing.libreswan.org"%endcert_name,
                                              START=dates['OK_NOW'],
                                              END=dates['FUTURE'])

                writeout_cert_and_key("certs/", endrev_name, ercert, erkey)
                store_cert_and_key(endrev_name, ercert, erkey)
                writeout_pkcs12("pkcs12/", endrev_name,
                                ercert, erkey, signpair[0])

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

    print("creating a CRL with a leading zero byte signature..")
    while True:
        good = False
        nl = ''

        crl = zerosig.export(signcert, signkey,
                             type=crypto.FILETYPE_TEXT, days=days, digest='sha256')
        der = zerosig.export(signcert, signkey,
                             type=crypto.FILETYPE_ASN1, days=days, digest='sha256')

        for index, line in enumerate(crl.splitlines()):
            if "Signature Algorithm" in line and index >= 5:
                nl = crl.splitlines()[index + 1].strip()
                if nl.startswith('00'):
                    good = True
                    break

        if good:
            print(nl)
            print("found after %d signatures!"% days)
            with open(dirbase + "crls/crl-leading-zero-byte.crl", "wb") as f:
                f.write(der)
            break

        days += 1


def create_crlsets():
    """ Create test CRLs
    """
    print("creating crl set")
    revoked = crypto.Revoked()
    chainrev = crypto.Revoked()
    future_revoked = crypto.Revoked()

    revoked.set_rev_date(dates['OK_NOW'].encode('utf-8'))
    chainrev.set_rev_date(dates['OK_NOW'].encode('utf-8'))
    future_revoked.set_rev_date(dates['FUTURE'].encode('utf-8'))
    # the get_serial_number method results in a hex str like '0x17'
    # but set_serial needs a hex str like '17'
    ser = hex(crypto.X509.from_cryptography(end_certs['revoked'][0]).get_serial_number())[2:]
    revoked.set_serial(ser.encode('utf-8'))
    ser = hex(crypto.X509.from_cryptography(end_certs['west_chain_revoked'][0]).get_serial_number())[2:]
    chainrev.set_serial(ser.encode('utf-8'))
    ser = hex(crypto.X509.from_cryptography(end_certs['revoked'][0]).get_serial_number())[2:]
    future_revoked.set_serial(ser.encode('utf-8'))

    needupdate = crypto.CRL()
    needupdate.add_revoked(revoked)
    needupdate.add_revoked(chainrev)
    with open(dirbase + "crls/needupdate.crl", "wb") as f:
        f.write(needupdate.export(crypto.X509.from_cryptography(ca_certs['mainca'][0]),
                                  crypto.PKey.from_cryptography_key(ca_certs['mainca'][1]),
                                  type=crypto.FILETYPE_ASN1,
                                  days=0, digest='sha256'.encode('utf-8')))

    print("sleeping for needupdate/valid crl time difference")
    time.sleep(5)
    validcrl = crypto.CRL()
    validcrl.add_revoked(revoked)
    validcrl.add_revoked(chainrev)
    with open(dirbase + "crls/cacrlvalid.crl", "wb") as f:
        f.write(validcrl.export(crypto.X509.from_cryptography(ca_certs['mainca'][0]),
                                crypto.PKey.from_cryptography_key(ca_certs['mainca'][1]),
                                type=crypto.FILETYPE_ASN1,
                                days=15, digest='sha256'.encode('utf-8')))

    othercrl = crypto.CRL()
    othercrl.add_revoked(revoked)
    othercrl.add_revoked(chainrev)
    with open(dirbase + "crls/othercacrl.crl", "wb") as f:
        f.write(othercrl.export(crypto.X509.from_cryptography(ca_certs['otherca'][0]),
                                crypto.PKey.from_cryptography_key(ca_certs['otherca'][1]),
                                type=crypto.FILETYPE_ASN1,
                                days=15, digest='sha256'.encode('utf-8')))

    notyet = crypto.CRL()
    notyet.add_revoked(future_revoked)
    with open(dirbase + "crls/futurerevoke.crl", "wb") as f:
        f.write(notyet.export(crypto.X509.from_cryptography(ca_certs['mainca'][0]),
                              crypto.PKey.from_cryptography_key(ca_certs['mainca'][1]),
                              type=crypto.FILETYPE_ASN1,
                              days=15, digest='sha256'.encode('utf-8')))

     #create_leading_zero_crl()



def run_dist_certs():
    """ Generate the pluto test harness x509
    certificates, p12 files, keys, and CRLs
    """
    # Add root CAs here
    basic_pluto_cas =  ('mainca', 'otherca', 'badca')
    # Add end certs here
    mainca_end_certs = ('nic','east','west', 'road', 'north', # standard certs
                        'west-eku-clientAuth', 'east-eku-clientAuth', # should be enough to validate
                        'west-eku-serverAuth', 'east-eku-serverAuth', # should be enough to validate
                        'west-bcOmit', 'eastbcOmit', # Basic Constraints should not be needed
                        'west-kuOmit', 'east-kuOmit', # Key Usage should not be needed
                        'west-ekuOmit', 'east-ekuOmit', # Extended Key Usage should not be needed
                        # openssl refuses to generate these
                        # 'west-kuEmpty', 'east-kuEmpty', # Key Usage may be empty
                        # 'west-ekuEmpty', 'east-ekuEmpty', # Extended Key Usage may be empty
                        'west-nosan', 'east-nosan', # No Subject Alt Names
                        'west-sanCritical', 'east-sanCritical', # should work
                        'west-bcCritical', 'east-bcCritical', # Basic Constraints critical flag should be ignored
                        'west-kuCritical', 'east-kuCritical', # Key Usage critical flag should be ignored
                        'west-ekuCritical', 'east-ekuCritical', # Extended Key Usage critical flag should be ignored ??
                        # openssl refuses to generate these
                        # 'west-kuBOGUS-bad', 'east-kuBOGUS-bad', # Should fail because it needs digitalSignature or nonRepudiation
                        'west-ku-keyAgreement-digitalSignature','east-ku-keyAgreement-digitalSignature', # Should work
                        'west-ku-keyAgreement-bad', 'east-ku-keyAgreement-bad', # Should fail without digitalSignature or nonRepudiation
                        'west-ku-nonRepudiation', 'east-ku-nonRepudiation', # Should work
                        'west-ekuBOGUS-bad', 'east-ekuBOGUS-bad', # Should fail because it needs a recognised EKU
                        # openssl refuses to generate these
                        # 'west-ku-nonRepudiation-kuBOGUS-bad', 'east-ku-nonRepudiation-kuBOGUS-bad', # Should fail
                        # 'west-eku-emailProtection-ekuBOGUS', 'east-eku-emailProtection-ekuBOGUS', # Should work
                        'west-eku-ipsecIKE', 'east-eku-ipsecIKE', # Should work
                        'west-ekuCritical-eku-ipsecIKE', 'east-ekuCritical-eku-ipsecIKE', # Should still work
                        'west-ekuCritical-eku-emailProtection', 'east-ekuCritical-eku-emailProtection', # Should still work
                        'usage-server', 'usage-client', 'usage-both',
                        'nic-noext', 'nic-nourl',
                        'smallkey', 'mediumkey', 'key2032', 'key4096',
                        'signedbyother','otherwest','othereast','wrongdnorg',
                        'unwisechar','spaceincn','hashsha1',
                        'cnofca','revoked', 'badwest', 'badeast', 'semiroad')
    # Add chain roots here
    chain_ca_roots =   ('east_chain', 'west_chain')

    # Put special case code for new certs in the following functions
    create_basic_pluto_cas(basic_pluto_cas)
    create_mainca_end_certs(mainca_end_certs)
    create_chained_certs(chain_ca_roots, 3)
    create_chained_certs(chain_ca_roots, 9, 'long_')
    create_chained_certs(chain_ca_roots, 10, 'too_long_')
    create_crlsets()

def create_nss_pw():
    print("creating nss-pw")
    f = open("nss-pw","w")
    f.write("foobar")
    f.close()

def main():
    outdir = os.path.dirname(sys.argv[0])
    cwd = os.getcwd()
    if outdir:
        os.chdir(outdir)
    global dates
    global dirbase
    reset_files()
    dates = gen_gmtime_dates()
    print("format dates being used for this run:")
    # TODO: print the display GMT times
    for n, s in dates.items():
        print("%s : %s"% (n, s))

    dirbase = ""
    run_dist_certs()

    create_nss_pw()

    print("finished!")

if __name__ == "__main__":
    main()
