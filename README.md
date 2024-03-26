# Cert Helper

A script to quickly make certificate signing requests (CSR).

Supported key types are RSA and EC (elliptic curve), defaulting to EC.

Optionally you can also immediately create a self-signed certificate.

This script uses the [cryptography], [click], and [PyYAML] libraries.

## Install and use

1. Install with `pip install cert-helper`
1. Run `cert-helper` once to generate the default `settings.yaml`
1. Modify `settings.yaml` to your needs.
1. Then run `cert-helper` to get started!

[cryptography]: https://cryptography.io/
[click]: https://click.palletsprojects.com/
[PyYAML]: https://pyyaml.org/
