import re
import ssl
import yaml
import time
import urllib.request
from datetime import datetime
import cryptography
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from prometheus_client import start_http_server, Gauge

def get_cert(url, port):
    return ssl.get_server_certificate((url, port))

def load_cert(file):
    c = x509.load_pem_x509_certificate(file.encode(), default_backend())
    return c

def load_cert_decode(file):
    c = x509.load_pem_x509_certificate(file, default_backend())
    return c

def get_serial_number(cert):
    return cert.serial_number

def get_clr_url(cert):
    crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    return re.findall("(http://[^']+)", str(crl))

def get_clr_file(url):
    with urllib.request.urlopen(url) as f:
        html = f.read()
    return html

def is_revoked(crl_file, serial_number):
    c = x509.load_der_x509_crl(crl_file, default_backend())
    r = c.get_revoked_certificate_by_serial_number(serial_number)
    if isinstance(r, cryptography.hazmat.backends.openssl.x509._RevokedCertificate):
        return True   
    else:
        return False

def check_certificate(site, port):
    file = get_cert(site, port)
    cert = load_cert(file)
    clr_urls = get_clr_url(cert)
    clr = get_clr_file(clr_urls[0])
    sn = get_serial_number(cert)

    g.labels(site).set(int(is_revoked(clr, sn)))

config_file = open("config.yml", 'r')
config_content = yaml.load(config_file, Loader=yaml.FullLoader)
g = Gauge('ssl_crl_is_revoked', 'Is the serial number of the certificate in crl file', ["site"])

if __name__ == '__main__':
    start_http_server(8000)
    while True:
        check_certificate(config_content["site"], config_content["port"])
        time.sleep(config_content["time"])
        