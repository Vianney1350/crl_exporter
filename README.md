# ssl_crl_exporter

This prometheus exporter check if the serial number of a x509 certificate is present in the CRL of his authority.

## Documentation
- [cryptography.io](https://cryptography.io/en/2.7/x509/reference/)
- [prometheus](https://github.com/prometheus/client_pythons)

## Test sites
- [grc.com](https://www.grc.com/default.htm)
- [badssl.com](https://badssl.com/)
- [digicert.com](https://www.digicert.com/kb/digicert-root-certificates.htm)