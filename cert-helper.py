#!/usr/bin/env python3
"""
Helper script for creating Certificate Signing Requests (CSR)

TODO: objectify!
"""
import datetime
import logging
import os
import re
import click
from yaml import safe_load, YAMLError
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


log_debug = os.environ.get("DEBUG")
logger = logging.getLogger('root')
if log_debug:
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(format="[%(filename)s:%(lineno)d	- %(funcName)20s() ] %(message)s")
else:
    logger.setLevel(logging.INFO)
    logging.basicConfig(format="%(message)s")

logger.debug('Initialising')

domain_regex = "^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$"

def load_settings():
    logger.debug('Loading settings')
    settings_file = Path('settings.yaml')
    with settings_file.open() as stream:
        try:
            data = safe_load(stream)
            return data
        except YAMLError as ye:
            logger.error(ye)


settings = load_settings()


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


def sanitise_path(name, suffix):
    logger.debug('Sanitise path (Path)')
    # First sanitise
    replace_wildcard = name.replace("*", "wildcard")

    # Then build path
    path = Path(f'out/{name}/{replace_wildcard}{suffix}')
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def validate_dnsname(name):
    match = re.search(domain_regex, name)
    if not match:
        logger.error(f"Domain '{name}' is invalid!")
        return
    return match.string


def get_key(name, key_type='ec'):
    """
    Generate private key.

    Because we do not want to overwrite any existing private keys, try to open the file first in exclusive write mode.
    If the key file already exists, FileExistsError is thrown, and we try to load the existing file instead.

    TODO: this is no longer the case... We first create an empty key file with 0600 permissions.
    """
    logger.debug('Get key file or generate a new key')
    key_file = sanitise_path(name, f'.{key_type}.pem')
    key_file.touch(0o600)

    try:
        key = private_key_load(key_file)
    except ValueError:
        logger.error(f"Private key file '{key_file.name}' does not contain correct private key, overwriting")

    try:
        with key_file.open(mode='wb') as f:
            key = get_mapping(key_type)()

            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except FileExistsError:
        logger.error(f"Private key file '{key_file.name}' already exists, loading contents")
        key = private_key_load(key_file)

    key_file.chmod(0o600)

    return key


def get_x509_name(name):
    nameoid = settings['nameoid']

    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, nameoid['COUNTRY_NAME']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, nameoid['STATE_OR_PROVINCE_NAME']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, nameoid['LOCALITY_NAME']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, nameoid['ORGANIZATION_NAME']),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])


def create_csr(name, san, key_type, force=False):
    """
    Create certificate signing request (CSR)
    :param name: the common name, also name of the certificate
    :param san: List[subjectAltNames]
    :param key_type: ec or rsa
    :param force: overwrite existing CSR
    :return: PEM encoded CSR
    """
    logger.debug('Build and sign the CSR')
    csr_file = sanitise_path(name, f'.csr.pem')

    logger.info("Creating certificate signing request")

    write_mode = 'wb' if force else 'xb'

    try:
        with csr_file.open(write_mode) as f:
            # Create new, or load existing key.
            key = get_key(name, key_type)

            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(get_x509_name(name))
            builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)

            logger.info('Signing CSR with key')
            csr = builder.sign(key, hashes.SHA256())
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)

            f.write(csr_pem)
            logger.info(f"Saved CSR '{csr_file.name}'")
    except FileExistsError:
        # TODO: this message doesn't make much sense when running in interactive mode.
        logger.error(f"CSR '{csr_file.name}' exists, not overwriting (use '-f' or '--force' to overwrite)")
        return

    logger.info("Your CSR:\n")
    print(csr_pem.decode('utf-8'))
    return csr_pem


def create_certificate(name, san, key_type, validity, force=False):
    """
    Create a *self signed* certificate
    @param name: common name
    @param key_type: key type of certificate
    @param san: subjectAltNames
    @param validity: certificate validity in days
    @param force: overwrite existing certificate
    """
    logger.debug('Build and sign certificate')
    cert_file = sanitise_path(name, '.crt.pem')

    write_mode = 'wb' if force else 'xb'

    try:
        with cert_file.open(write_mode) as f:
            x509_name = get_x509_name(name)
            key = get_key(name, key_type=key_type)
            now = datetime.datetime.now()
            end_date = now + datetime.timedelta(days=validity)

            cert = x509.CertificateBuilder()
            cert = cert.subject_name(x509_name)
            cert = cert.issuer_name(x509_name)
            cert = cert.public_key(key.public_key())
            cert = cert.serial_number(x509.random_serial_number())
            cert = cert.not_valid_before(now)
            cert = cert.not_valid_after(end_date)
            cert = cert.add_extension(x509.SubjectAlternativeName(san), critical=False)

            cert = cert.sign(key, hashes.SHA256())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            f.write(cert_pem)
            logger.info(f"Saved certificate '{cert_file.name}'")
    except FileExistsError:
        # TODO: this message doesn't make much sense when running in interactive mode.
        logger.error(f"Certificate '{cert_file.name}' exists, not overwriting (use '-f' or '--force' to overwrite)")
        return

    logger.info("Your certificate:\n")
    print(cert_pem.decode('utf-8'))
    return cert_pem


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
    san = [
        x509.DNSName('example.org'),
        x509.DNSName('*.example.org'),
        x509.DNSName('example.net')
    ]
    create_csr('test', san, 'ec', True)
    create_certificate('test', san, 'ec', 10, True)


@cli.command()
def interactive(force=False):
    """
    Create CSR interactively
    """
    logger.debug("Run CLI interactive")
    common_name = click.prompt("What is the primary domain?", type=str)
    while not (validate_dnsname(common_name)):
        common_name = click.prompt("What is the primary domain?", type=str)
    key_type = click.prompt("What type of key to use? ('ec' or 'rsa')", default='ec')
    self_signed = click.prompt("Do you want to create self-signed certificate?", type=bool, default=False)

    more_altnames = True
    altnames = [x509.DNSName(common_name)]
    while more_altnames:
        this_name = click.prompt("Please enter any additional names", type=str, default="")
        if not this_name:
            more_altnames = False
        else:
            if (validate_dnsname(this_name)):
                    altnames.append(x509.DNSName(this_name))

    if not (create_csr(common_name, altnames, key_type)):
        overwrite = click.prompt("CSR for this domain already exists, overwrite it?", type=bool,default=False)
        if overwrite:
            create_csr(common_name, altnames, key_type, overwrite)

    if self_signed:
        validity = click.prompt("How long do you want the certificate to be valid for?", type=int, default=365)
        if not (create_certificate(common_name, altnames, key_type, validity)):
            overwrite = click.prompt("Certificate for this domain already exists, overwrite it?", type=bool,default=False)
            if overwrite:
                create_certificate(common_name, altnames, key_type, validity, overwrite)


help_text_domain = "Domain to create a CSR for. Can be passed multiple times, " \
                   "the first entry will be the primary domain"
help_text_type   = "Type of key to generate. 'rsa' or 'ec', defaults to 'ec'"
help_text_sign = "Create self-signed certificate?"


@cli.command()
@click.option('--domain', '-d', multiple=True, required=True, help=help_text_domain)
@click.option('--type', '-t', 'key_type', default='ec', help=help_text_type)
@click.option('--sign', '-s', is_flag=True, type=bool, help=help_text_sign)
@click.option('--validity', '-v', is_flag=True, default=365, type=int, help="Length of certificate validity, in days")
@click.option('--force', '-f', is_flag=True, type=bool, help="Overwrite existing CSR and certificate, if present", default=False)
def create(domain, key_type, sign, validity, force):
    """
    Pass domains to create without going interactive
    """
    logger.debug("Run CLI create")
    common_name = domain[0].strip("'")
    altnames = []
    error = False

    for d in domain:
        if re.search(domain_regex, d):
            altnames.append(x509.DNSName(d))
        else:
            logger.error(f"Domain '{d}' is invalid!")
            error = True
    if error:
        exit(1)

    create_csr(common_name, altnames, key_type, force)

    if sign:
        create_certificate(common_name, altnames, key_type, validity, force)


if __name__ == '__main__':
    cli()
