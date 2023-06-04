# Cert Helper

A script to quickly make a private key and certificate signing request (CSR).

Supported key types are RSA and EC (elliptic curve).

This script uses the [cryptography], [click], and [PyYAML] libraries.

## Install and use

1. Install `pipenv` with `pip install pipenv`
1. Run `pipenv install`
1. Copy [settings.sample.yaml](settings.sample.yaml) to `settings.yaml` and modify to your needs.
1. Then run `python cert-helper.py` to get started!

[cryptography]: https://cryptography.io/
[click]: https://click.palletsprojects.com/
[PyYAML]: https://pyyaml.org/
