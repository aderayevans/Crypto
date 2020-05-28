from OpenSSL import crypto, SSL
from socket import gethostname

CERT_FILE = "quangb1510210.crt"
KEY_FILE = "privatekey.pem"

def create_self_signed_cert():

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "VN"
    cert.get_subject().ST = "CanTho"
    cert.get_subject().L = "NinhKieu"
    cert.get_subject().O = "NewWay Company Ltd."
    cert.get_subject().OU = "Administration Department"
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(50*365*24*60*60-8219*24*60*60+42*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'SHA256')

    open(CERT_FILE, "wb").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(KEY_FILE, "wb").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

create_self_signed_cert()
print('done')