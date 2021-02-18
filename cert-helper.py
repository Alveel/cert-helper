#!/usr/bin/env python3

import click
from yaml import safe_load, YAMLError
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def load_settings():
    with open('settings.yaml', 'r') as stream:
        try:
            data = safe_load(stream)
            return data
        except YAMLError as ye:
            print(ye)


def generate_key(name, key_type='ec'):
    """
    TODO: work with RSA as well
    """
    print(f"Generating private key '{name}.ecc.pem'")
    key = ec.generate_private_key(
        ec.SECP256R1()
    )

    with open(f'out/{name}.ecc.pem', 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return key


def create_csr(name, settings, san, key=False):
    """
    Create certificate signing request (CSR)
    :param name: the common name, also name of the certificate
    :param settings: NameOID settings
    :param san: List[subjectAltNames]
    :param key: private key
    :return:
    """
    print("Creating certificate signing request")
    nameoid = settings['nameoid']

    if not key:
        # Generate key if not already specified
        key = generate_key(name)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, nameoid['COUNTRY_NAME']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, nameoid['STATE_OR_PROVINCE_NAME']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, nameoid['LOCALITY_NAME']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, nameoid['ORGANIZATION_NAME']),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ]))

    builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(f'out/{name}.csr.pem', 'wb') as f:
        f.write(csr_pem)

    print(f"Saved CSR {name}.csr.pem")
    print(csr_pem.decode('utf-8'))
    return csr_pem


def run():
    """
    Test run function with static names.
    """
    settings = load_settings()
    san = [
        x509.DNSName('example.org'),
        x509.DNSName('*.example.org'),
        x509.DNSName('example.net')
    ]
    create_csr('test', settings, san)


@click.command()
def interactive():
    """
    Interactive function that asks for alt names.
    """
    settings = load_settings()
    common_name = click.prompt('What is the primary domain?', type=str)

    more_altnames = True
    altnames = [x509.DNSName(common_name)]
    while more_altnames:
        this_name = click.prompt('Please enter any additional names', type=str, default="")
        if not this_name:
            more_altnames = False
        else:
            altnames.append(x509.DNSName(this_name))

    create_csr(common_name, settings, altnames)


@click.command()
@click.option('--domain', '-d', multiple=True)
def names(domain):
    """
    Pass every domain you want to add
    :param domain: name
    """
    common_name = domain[0]
    altnames = []
    for d in domain:
        altnames.append(x509.DNSName(d))

    create_csr(common_name, load_settings(), altnames)


if __name__ == '__main__':
    # interactive()
    names()
