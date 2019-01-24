"""
extracts ca, cert, and key from an ovpn file

usage: ovpn_p12extractor.py config.ovpn
expected output: ca.crt, cert.crt, key.key, and p12certificate.p12
"""

import sys
from OpenSSL import crypto

if len(sys.argv) <= 1:
    print("Required argument: .ovpn config filename missing!\nUsage: ovpn_p12extractor.py config.ovpn")


else:

    with open(sys.argv[1]) as f:
        data = f.read()
        # split up the <ca>, <cert>, and <key> sections
        ca = data.split("<ca>")[1].split("</ca>")[0]
        cert = data.split("<cert>")[1].split("</cert>")[0]
        key = data.split("<key>")[1].split("</key>")[0]

        # write the to files
        # with open("ca.crt", "w") as ca_file:
        #     ca_file.write(ca)
        # with open("cert.crt", "w") as cert_file:
        #     cert_file.write(cert)
        # with open("key.key", "w") as key_file:
        #     key_file.write(key)

        print("ca.crt, cert.crt, key.key created \nUsing OpenSSL to combine them into a p12")
        # load ca, cert, and key files
        ca = crypto.load_certificate(crypto.FILETYPE_PEM, bytes(ca, encoding='utf-8'))
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, bytes(cert, encoding='utf-8'))
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, bytes(key, encoding='utf-8'))
        # combine into p12 format
        p12 = crypto.PKCS12Type()
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        p12.set_ca_certificates([ca])
        # write to p12 file
        passphrase = str(input('Passphrase for p12: '))
        print('Exporting p12certificate.p12')
        p12data = p12.export(passphrase)
        with open('p12certificate.p12', 'wb') as p12file:
            p12file.write(p12data)
