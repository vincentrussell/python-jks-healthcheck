import click
import jks
import OpenSSL
from socket import AF_INET, AF_INET6, error, socket
from os import path
from sys import exit
from OpenSSL.SSL import (
    Context, Session, Connection, SSLeay_version)

_ASN1 = OpenSSL.crypto.FILETYPE_ASN1

@click.command()
@click.option('--keystore', required=True, help='Keystore')
@click.option('--keystoreAlias', required=False, help='Keystore Alias')
@click.option('--keyPass', required=False, help='Key Passprhase')
@click.option('--keystorePassphrase', required=True, help='Keystore Passphrase')
@click.option('--hostAndPort', required=True, help='Host and port to try to connect to, i.e; 127.0.0.1:443')
@click.option('--timeout', required=False, help='Timeout in seconds while trying to connect', default=10)
def start(keystore, keystorealias, keypass, keystorepassphrase, hostandport, timeout):
    verify(keystore, keystorealias, keypass, keystorepassphrase, hostandport)
    sslContext = getOpensslContext(keystore, keystorealias, keypass, keystorepassphrase)
    socket = socket_any_family()
    socket.settimeout(timeout)
    hostandport = hostandport.split(":", 2)
    socket.connect((hostandport[0], int(hostandport[1])))
    sslConnection = Connection(sslContext, socket)
    sslConnection.set_connect_state()
    sslConnection.set_tlsext_host_name(hostandport[0].encode('utf-8'))
    sslConnection.do_handshake()
    sslContext.set_timeout(timeout)
    sslConnection.send(b"GET / HTTP/1.0\r\n\r\n")
    socket.recv(1024)

def getOpensslContext(keystore, keystorealias, keypass, keystorepassphrase):
    keystoreObj = jks.KeyStore.load(keystore, keystorepassphrase)
    keyPassPhrase = keystorepassphrase
    retval = None
    if keypass:
        keyPassPhrase = keypass

    pk_entry = None
    if keystorealias:
        pk_entry = keystoreObj.private_keys[keystorealias]
    else:
        pk_entry = keystoreObj.private_keys[0]

    if not pk_entry.is_decrypted():
        pk_entry.decrypt(keyPassPhrase)

    pkey = OpenSSL.crypto.load_privatekey(_ASN1, pk_entry.pkey)

    public_cert = OpenSSL.crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
    ctx.use_privatekey(pkey)
    ctx.use_certificate(public_cert)
    ctx.check_privatekey() # want to know ASAP if there is a problem
    cert_store = ctx.get_cert_store()
    for key in keystoreObj.certs:
        other_trusted_cert = OpenSSL.crypto.load_certificate(_ASN1, keystoreObj.certs[key].cert)
        cert_store.add_cert(other_trusted_cert)
    return ctx


def socket_any_family():
    try:
        return socket(AF_INET)
    except error as e:
        if e.errno == EAFNOSUPPORT:
            return socket(AF_INET6)
        raise


def verify(keystore, keystorealias, keypass, keystorepassphrase, hostandport):
    if not path.exists(keystore):
        print("keystore file " + keystore + " not found")
        exit(1)
    if not hostandport:
        print("hostname and port must be provided")
        exit(1)
    hostandport = hostandport.split(":", 2)
    if not len(hostandport) == 2:
        print("hostAndPort is not in proper format, i.e:localhost:443")
    if not hostandport[1].isnumeric():
        print("hostAndPort is not in proper format.  The port is not a number.")

if __name__ == '__main__':
    start()