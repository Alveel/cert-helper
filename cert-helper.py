#!/usr/bin/env python3
"""
Helper script for creating Certificate Signing Requests (CSR)

TODO: objectify!
"""

import logging
import click
from yaml import safe_load, YAMLError
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


logger = logging.getLogger('root')
log_format = f"[%(filename)s:%(lineno)d	- %(funcName)20s() ] %(message)s"
logging.basicConfig(format=log_format)
logger.setLevel(logging.DEBUG)
logger.debug('Initialising')


def load_settings():
    logger.debug('Loading settings')
    settings_file = Path('settings.yaml')
    with settings_file.open() as stream:
        try:
            data = safe_load(stream)
            return data
        except YAMLError as ye:
            logger.error(ye)


def private_key_load(key_file_path: Path):
    """
    Load private key, independent of type.
    :param key_file_path: Path to key file
    :return: RSAPrivateKey or EllipticCurvePrivateKey
    """
    logger.debug('Loading private key file')
    with key_file_path.open(mode='rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def create_ec_key():
    logger.debug('Generating EC')
    return ec.generate_private_key(
        ec.SECP256R1()
    )


def create_rsa_key(length=4096):
    logger.debug('Generating RSA')
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


def get_out_dir(name: str):
    logger.debug('Get out dir (str)')
    suffixes = [".csr.pem", ".ec.pem"]
    out_dir = "out/" + name
    for suf in suffixes:
        out_dir = out_dir.removesuffix(suf)

    return out_dir


def sanitise_path(name):
    logger.debug('Sanitise path (Path)')
    # First sanitise
    replace_wildcard = name.replace("*", "wildcard")

    # Then build path
    outpath = get_out_dir(replace_wildcard)
    path = Path(f'{outpath}/{replace_wildcard}')
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def get_key(name, key_type='ec'):
    """
    Generate private key.

    Because we do not want to overwrite any existing private keys, try to open the file first in exclusive write mode.
    If the key file already exists, FileExistsError is thrown, and we try to load the existing file instead.
    """
    logger.debug('Get key file or generate a new key')
    key_file = sanitise_path(f'{name}.{key_type}.pem')

    try:
        with key_file.open(mode='xb') as f:
            create_func = get_mapping(key_type)
            key = create_func()

            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except FileExistsError:
        logger.error(f"Private key file '{key_file.name}' already exists, loading contents")
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
    logger.debug('Build and sign the CSR')
    csr_file = sanitise_path(f'/{name}.csr.pem')

    logger.info("Creating certificate signing request")
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
    logger.info('Signing CSR with key')
    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    write_mode = 'wb' if force else 'xb'

    try:
        with csr_file.open(write_mode) as f:
            f.write(csr_pem)
            logger.info(f"Saved CSR '{csr_file.name}'")
    except FileExistsError:
        logger.error(f"CSR '{csr_file.name}' exists, not overwriting (use '-f' or '--force' to overwrite)")
        return

    logger.info("Your CSR:\n")
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
    logger.debug('Run CLI debug')
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
    Create CSR interactively
    """
    logger.debug('Run CLI interactive')
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
    logger.debug('Run CLI create')
    settings = load_settings()
    common_name = domain[0].strip("'")
    altnames = []
    for d in domain:
        altnames.append(x509.DNSName(d))

    create_csr(common_name, settings, altnames, key_type, force)


if __name__ == '__main__':
    cli()
