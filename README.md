# Cert Helper

A script to quickly make a private key and certificate signing request (CSR).

Supported key types are RSA and EC (elliptic curve).

This script uses the [click] and [cryptography] libraries.

## Install and use

1. Install in a virtualenv with `pip install -r requirements.txt`.
1. Copy [settings.sample.yaml](settings.sample.yaml) to `settings.yaml` and modify to your needs.
1. Then run `python cert-helper.py` to get started!

[click]: https://click.palletsprojects.com/
[cryptography]: https://cryptography.io/
