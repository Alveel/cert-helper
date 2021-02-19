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
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


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
    """
    Translate key_type to the appropriate create_key function
    :param key_type: the type of key
    :return: the create_key function
    """
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
            print(f"Generating private key '{key_file.name}'")
            create_func = get_mapping(key_type)
            key = create_func()

            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except FileExistsError:
        print(f"Private key file '{key_file.name}' already exists, loading contents")
        key = private_key_load(key_file)

    return key


def create_csr(name, settings, san, key_type, force=False):
    """
    Create certificate signing request (CSR)
    :param name: the common name, also name of the certificate
    :param settings: NameOID settings
    :param san: List[subjectAltNames]
    :param key_type: ec or rsa
    :param force: overwrite existing CSR
    :return: PEM encoded CSR
    """
    print("Creating certificate signing request")
    nameoid = settings['nameoid']

    # Create new, or load existing key.
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
    print('Signing CSR with key')
    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    write_mode = 'wb' if force else 'xb'

    try:
        with open(f'out/{name}.csr.pem', write_mode) as f:
            f.write(csr_pem)
            print(f"Saved CSR '{name}.csr.pem'")
    except FileExistsError:
        print(f"CSR '{name}.csr.pem' exists, not overwriting (use '-f' or '--force' to overwrite)")
        return

    print("Your CSR:\n")
    print(csr_pem.decode('utf-8'))
    return csr_pem


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(
    context_settings=CONTEXT_SETTINGS,
    help="Helper script for creating Certificate Signing Requests (CSR)"
)
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
@click.option('--force', '-f', is_flag=True, help="Overwrite existing CSR, if present")
def interactive(force):
    """
    Create CSR interactively (default)
    """
    settings = load_settings()
    key_type = click.prompt("What type of key to use? ('ec' or 'rsa')", default='ec')
    common_name = click.prompt('What is the primary domain?', type=str)

    more_altnames = True
    altnames = [x509.DNSName(common_name)]
    while more_altnames:
        this_name = click.prompt('Please enter any additional names', type=str, default="")
        if not this_name:
            more_altnames = False
        else:
            altnames.append(x509.DNSName(this_name))

    create_csr(common_name, settings, altnames, key_type, force)


create_help_text = "Domain to create a CSR for. Should be passed multiple times, " \
                   "the first entry will be the primary domain."


@cli.command()
@click.option('--domain', '-d', multiple=True, required=True, help=create_help_text)
@click.option('--type', '-t', 'key_type', default='ec', help="Type of key to generate. 'rsa' or 'ec', defaults to 'ec'")
@click.option('--force', '-f', is_flag=True, help="Overwrite existing CSR, if present")
def create(domain, key_type, force):
    """
    Pass domains to create without going interactive
    """
    settings = load_settings()
    common_name = domain[0]
    altnames = []
    for d in domain:
        altnames.append(x509.DNSName(d))

    create_csr(common_name, settings, altnames, key_type, force)


if __name__ == '__main__':
    cli()
