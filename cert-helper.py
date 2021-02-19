#!/usr/bin/env python3
"""
Helper script for creating Certificate Signing Requests (CSR)
"""

import click
from yaml import safe_load, YAMLError
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def load_settings():
    settings_file = Path('settings.yaml')
    with settings_file.open() as stream:
        try:
            data = safe_load(stream)
            return data
        except YAMLError as ye:
            print(ye)


def private_key_load(key_file_path: Path):
    """
    Load private key, independent of type.
    :param key_file_path: Path to key file
    :return: RSAPrivateKey or EllipticCurvePrivateKey
    """
    with key_file_path.open(mode='rb') as f:
        key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    return key


def create_ec_key():
    return ec.generate_private_key(
        ec.SECP256R1()
    )


def create_rsa_key(length=4096):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=length,
    )


def get_mapping(key_type):
    mapping = {
        'ec': create_ec_key,
        'rsa': create_rsa_key,
    }

    return mapping[key_type]


def get_key(name, key_type='ec'):
    """
    Generate private key.

    Because we do not want to overwrite any existing private keys, try to open the file first in exclusive write mode.
    If the key file already exists, FileExistsError is thrown, and we try to load the existing file instead.
    """
    key_file = Path(f'out/{name}.{key_type}.pem')

    try:
        with key_file.open(mode='xb') as f:
            print(f"Generating private key '{key_file.name}")
            create_func = get_mapping(key_type)
            key = create_func()

            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except FileExistsError as fee:
        print(fee.strerror)
        print("Private key file already exists, trying to load contents...")
        key = private_key_load(key_file)

    return key


def create_csr(name, settings, san, key_type):
    """
    Create certificate signing request (CSR)
    :param name: the common name, also name of the certificate
    :param settings: NameOID settings
    :param san: List[subjectAltNames]
    :param key_type: ec or rsa
    :return: PEM encoded CSR
    """
    print("Creating certificate signing request")
    nameoid = settings['nameoid']

    # Create or load existing key.
    key = get_key(name, key_type)

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


@click.group()
def cli():
    pass


@cli.command()
def debug():
    """
    Debug function with static domains
    """
    settings = load_settings()
    san = [
        x509.DNSName('example.org'),
        x509.DNSName('*.example.org'),
        x509.DNSName('example.net')
    ]
    create_csr('test', settings, san, 'ec')


@cli.command()
def interactive():
    """
    Create CSR interactively
    """
    settings = load_settings()
    key_type = click.prompt("What type of key to use? ('ec' or 'rsa', defaulting to 'ec')", default='ec')
    common_name = click.prompt('What is the primary domain?', type=str)

    more_altnames = True
    altnames = [x509.DNSName(common_name)]
    while more_altnames:
        this_name = click.prompt('Please enter any additional names', type=str, default="")
        if not this_name:
            more_altnames = False
        else:
            altnames.append(x509.DNSName(this_name))

    create_csr(common_name, settings, altnames, key_type)


@cli.command()
@click.option('--domain', '-d', multiple=True, help="Domain to create a CSR for. Can be passed multiple times, the first entry will be the primary domain.")
@click.option('--type', '-t', 'key_type', default='ec', help="Type of key to generate. 'rsa' or 'ec', defaults to 'ec'")
def create(domain, key_type):
    """
    Potato Tomato
    """
    common_name = domain[0]
    altnames = []
    for d in domain:
        altnames.append(x509.DNSName(d))

    create_csr(common_name, load_settings(), altnames, key_type)


if __name__ == '__main__':
    cli()
