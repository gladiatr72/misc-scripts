#!/usr/bin/env python

from __future__ import print_function

from OpenSSL import crypto
import base64
import yaml
import os
import sys

FT_PEM = crypto.FILETYPE_PEM

KUBE_CFG = os.path.join(
    os.environ.get('HOME', '/'),
    '.kube',
    'config')


def export_p12(ca_cert, client_cert, client_key, passphrase='pass'):

    client_p12 = crypto.PKCS12()

    ca_cert_obj = crypto.load_certificate(FT_PEM, ca_cert)
    client_cert_obj = crypto.load_certificate(FT_PEM, client_cert)
    client_key_obj = crypto.load_privatekey(FT_PEM, client_key)

    client_p12.set_ca_certificates([ca_cert_obj])
    client_p12.set_certificate(client_cert_obj)
    client_p12.set_privatekey(client_key_obj)

    cp12 = client_p12.export(passphrase=passphrase, iter=2048, maciter=1024)

    return cp12


def main():
    with open(KUBE_CFG) as fh:
        bits = yaml.load(fh)

    if len(sys.argv) != 2:
        print('cluster name required', file=sys.stderr)
        sys.exit(1)
    else:
        cluster_name = sys.argv[1]

    clusters = bits['clusters']
    users = bits['users']

    cluster_ = [cl for cl in clusters if cl['name'] == cluster_name]

    if not cluster_:
        print('{} not found'.format(cluster_name), file=sys.stderr)
        sys.exit(1)
    else:
        cluster = cluster_.pop()

    ca_cert = base64.decodestring(
        cluster['cluster']['certificate-authority-data']
    )

    client_cert_dat = [
        (
            base64.decodestring(udat['user']['client-certificate-data']),
            base64.decodestring(udat['user']['client-key-data']),
        )
        for udat in users
        if udat['name'] == cluster_name
    ][0]

    cert, key = client_cert_dat

    cert_bin = export_p12(ca_cert, cert, key)

    with open('client__{}.p12'.format(cluster_name), 'wb') as fh:
        fh.write(cert_bin)

    return True


if __name__ == '__main__':
    print(main())








