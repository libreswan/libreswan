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

"""

import os
import sys
import shutil
import pexpect

dirbase=""

def reset_files():
    for dir in ['openssl',
                'openssl/keys/',
                'openssl/cacerts/',
                'openssl/certs/',
                'openssl/pkcs12/',
                'openssl/pkcs12/mainec', ]:
        if os.path.isdir(dir):
            shutil.rmtree(dir)
        os.mkdir(dir)

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

def create_ED25519_certs():
    """ The OpenSSL module doesn't appear to have
    support for curves so we do it with pexpect
    """
    # skip for non-base for now
    if dirbase != '':
        return

    print("creating ED25519 certs")
    #create CA

    run('openssl genpkey -algorithm ed25519'
        ' -outform PEM -out keys/ED25519CA.key')
    run('openssl req -x509 -new '
        '-key keys/ED25519CA.key '
        '-out cacerts/ED25519CA.crt '
        '-days 3650 -set_serial 1',
        # must match create_root_ca(<<mainca>>)
        events = {
            'Country Name': 'CA\r',
            'State': 'Ontario\r',
            'Locality': 'Toronto\r',
            'Organization': 'Libreswan\r',
            'Organizational': 'Test Department\r',
            'Common': 'Libreswan test CA for mainca\r',
            'Email': 'testing@libreswan.org\r',
        })
    serial = 2
    for name in ['east', 'west', 'north', 'road']:
        print("- creating %s-ED25519"% name)
        #create end certs
        pexpect.run('openssl genpkey -algorithm ed25519'
                    '-outform PEM -out keys/' + name +'-ed25519.key')

        child = pexpect.spawn('openssl req -config openssl.cnf -x509 '
                              '-new -key keys/ED25519CA.key '
                              '-out certs/' + name +
                              '-ed25519.crt -days 365 -set_serial ' +
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
                    '-inkey keys/%s-ed25519.key '
                    '-in certs/%s-ed25519.crt -name %s-ed25519 '
                    '-certfile cacerts/ED25519CA.crt '
                    '-caname "ed25519ca" '
                    '-out pkcs12/curveca/%s-ed25519.p12 '
                    '-passin pass:foobar -passout pass:foobar'
                    % (name, name, name, name))


def create_mainED25519_certs():
    """ The OpenSSL module doesn't appear to have
    support for curves so we do it with pexpect
    """

    print("creating main ED25519 root cert")

    #create CA
    run('openssl genpkey '
        '-algorithm ed25519 '
        '-outform PEM '
        '-out keys/mainED25519.key')
    run('openssl req -x509 -new '
        '-key keys/mainED25519.key '
        '-out cacerts/mainED25519.crt '
        '-days 3650 -set_serial 1',
        # must match create_root_ca(<<mainca>>)
        events = {
            'Country Name': 'CA\r',
            'State': 'Ontario\r',
            'Locality': 'Toronto\r',
            'Organization': 'Libreswan\r',
            'Organizational': 'Test Department\r',
            'Common': 'Libreswan test CA for mainca\r',
            'Email': 'testing@libreswan.org\r',
        })
    run('openssl pkcs12 -export '
        '-inkey keys/mainED25519.key '
        '-in cacerts/mainED25519.crt '
        '-name mainED25519 '
        '-certfile cacerts/mainED25519.crt '
        '-caname "mainED25519" '
        '-out pkcs12/mainec/mainED25519.p12 '
        '-passin pass:foobar -passout pass:foobar')

    print("creating main ED25519 end certs")

    serial = 2
    for name in ['east', 'west', 'north', 'road']:
        print("- creating %s-mainED25519"% name)
        run('openssl genpkey '
            '-algorithm ed25519 '
            '-outform PEM '
            '-out keys/'+name+'-mainED25519.key ')
        run('openssl req '
            '-config '+os.getcwd()+'/openssl.cnf '
                                   '-x509 '
                                   '-new '
                                   '-key keys/'+name+'-mainED25519.key '
                                                     '-out certs/'+name+'-mainED25519.crt '
                                                                        '-days 365 '
                                                                        '-set_serial '+str(serial),
            # must match create_mainca_end_certs()
            events = {
                'Country Name': 'CA\r',
                'State': 'Ontario\r',
                'Locality': 'Toronto\r',
                'Organization': 'Libreswan\r',
                'Organizational': 'Test Department\r',
                'Common': name + '.testing.libreswan.org\r',
                'Email': 'user-'+name+'@testing.libreswan.org\r',
            })

        serial += 1
        #package p12
        run('openssl pkcs12 -export '
            '-inkey keys/'+name+'-mainED25519.key '
                                '-in certs/'+name+'-mainED25519.crt '
                                                  '-name '+name+'-mainED25519 '
                                                                '-certfile cacerts/mainED25519.crt '
                                                                '-caname "mainED25519" '
                                                                '-out pkcs12/mainec/'+name+'-mainED25519.p12 '
                                                                                           '-passin pass:foobar -passout pass:foobar')

def main():
    outdir = os.path.dirname(sys.argv[0])
    cwd = os.getcwd()
    if outdir:
        os.chdir(outdir)

    global dirbase
    reset_files()

    dirbase = "openssl/"
    create_mainED25519_certs()

    print("finished!")

if __name__ == "__main__":
    main()
