#!/usr/bin/env python3
"""
Helper script for creating Certificate Signing Requests (CSR)

TODO: objectify!
"""
import datetime
import logging
import os
import re
import sys
from pathlib import Path
import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from yaml import safe_load, YAMLError, safe_dump

FORCE_HINT = "Delete or run with '--force' or '-f' to overwrite."

log_debug = os.environ.get("DEBUG")
logger = logging.getLogger("root")
if log_debug:
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(
        format="[%(filename)s:%(lineno)d	- %(funcName)20s() ] %(message)s"
    )
else:
    logger.setLevel(logging.INFO)
    logging.basicConfig(format="%(message)s")

logger.debug("Initialising")
settings = {}

# Regex from validators library, adjusted to allow wildcard domains.
domain_regex = re.compile(
    r"^(\*\.)?(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\."
    r"([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$"
)


def load_settings():
    """
    Load settings.yaml
    @return: dict with nameoid configuration
    """
    logger.debug("Loading settings")
    settings_file_str = os.environ.get("CERT_HELPER_SETTINGS", "settings.yaml")
    settings_file = Path(settings_file_str)
    try:
        with settings_file.open(encoding="utf-8") as stream:
            try:
                data = safe_load(stream)
                return data
            except YAMLError as yaml_err:
                logger.error(yaml_err)
                sys.exit(3)
    except FileNotFoundError:
        create_missing = click.prompt(f"Settings file {settings_file.absolute()} not found. Do you want to create it?", default=False)
        if create_missing:
            create_settings_file(settings_file=settings_file)
        else:
            logger.error("File does not exist and not creating, exiting.")
            sys.exit(0)


def private_key_load(key_file_path: Path):
    """
    Load private key, independent of type.
    @param key_file_path: Path to key file
    @return: RSAPrivateKey or EllipticCurvePrivateKey
    """
    logger.debug("Loading private key file")
    with key_file_path.open(mode="rb") as file:
        return serialization.load_pem_private_key(file.read(), password=None)


def create_ec_key() -> EllipticCurvePrivateKey:
    """
    Generate an elliptic curve private key and return it.
    @return: EllipticCurvePrivateKey
    """
    logger.debug("Generating EC")
    return ec.generate_private_key(ec.SECP256R1())


def create_rsa_key(length=4096) -> RSAPrivateKey:
    """
    Generate an RSA private key of specified length and return it.
    @param length: the length of the private key. Should be no shorter than 2048.
    @return: RSAPrivateKey
    """
    logger.debug("Generating RSA")
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=length,
    )


def get_mapping(key_type: str) -> EllipticCurvePrivateKey | RSAPrivateKey:
    """
    Translate key_type to the appropriate create_key function
    @param key_type: the type of key
    @return: the create_key function
    """
    mapping = {
        "ec": create_ec_key,
        "rsa": create_rsa_key,
    }

    return mapping[key_type]()


def sanitise_path(name: str, suffix: str) -> Path:
    """
    If our primary domain name is a wildcard, we should replace '*'
    with literal "wildcard".
    """
    logger.debug("Sanitise path (Path)")
    # First sanitise
    replace_wildcard = name.replace("*", "wildcard")

    # Then build path
    path = Path(f"out/{name}/{replace_wildcard}{suffix}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def validate_dnsname(name: str) -> bool:
    """
    Return whether or not given value is a valid domain.

    If the value is valid domain name this function returns ``True``.
    """
    match = re.search(domain_regex, name)
    if not match:
        logger.error("Domain '%s' is invalid!", name)
        return False
    return True


def get_key(name: str, key_type="ec"):
    """
    Generate private key.

    Touch the key file with "0600" permissions, try to load an existing key from it,
    otherwise generate a new key.
    """
    logger.debug("Get key file or generate a new key")
    key_file = sanitise_path(name, f".{key_type}.pem")
    key_file.touch(0o600)
    key_file_stat = key_file.stat()

    if key_file_stat.st_size > 0:
        logger.debug("Trying to load existing key file")
        try:
            return private_key_load(key_file)
        except ValueError:
            logger.error(
                "Private key file '%s' does not contain valid private key! (%s)",
                key_file.name,
                "Manually remove the file to generate a new key",
            )
            sys.exit(2)

    try:
        with key_file.open(mode="wb") as file:
            key = get_mapping(key_type)

            file.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    except FileExistsError:
        logger.error(
            "Private key file '%s' already exists, loading contents", key_file.name
        )
        key = private_key_load(key_file)

    key_file.chmod(0o600)

    return key


def get_x509_name(name) -> x509.Name:
    """
    Create the x509 certificate
    """
    global settings
    nameoid = settings["nameoid"]

    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, nameoid["COUNTRY_NAME"]),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, nameoid["STATE_OR_PROVINCE_NAME"]
            ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, nameoid["LOCALITY_NAME"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, nameoid["ORGANIZATION_NAME"]),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, nameoid["ORGANIZATIONAL_UNIT"]
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )


def create_csr(name, san, key_type, force=False):
    """
    Create certificate signing request (CSR)
    :param name: the common name, also name of the certificate
    :param san: List[subjectAltNames]
    :param key_type: ec or rsa
    :param force: overwrite existing CSR
    :return: PEM encoded CSR
    """
    logger.debug("Build and sign the CSR")
    csr_file = sanitise_path(name, ".csr.pem")

    logger.info("Creating certificate signing request")

    write_mode = "wb" if force else "xb"

    try:
        with csr_file.open(write_mode) as file:
            # Create new, or load existing key.
            key = get_key(name, key_type)

            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(get_x509_name(name))
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san), critical=False
            )

            logger.info("Signing CSR with key")
            csr = builder.sign(key, hashes.SHA256())
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)

            file.write(csr_pem)
            logger.info("Saved CSR '%s'", csr_file.name)
    except FileExistsError:
        logger.error(
            "Re-using existing CSR '%s'. (%s)",
            csr_file.name,
            FORCE_HINT,
        )
        return

    logger.info("Your CSR:\n")
    print(csr_pem.decode("utf-8"))


def create_certificate(name, san, key_type, validity, force=False):
    """
    Create a *self-signed* certificate
    @param name: common name
    @param key_type: key type of certificate
    @param san: subjectAltNames
    @param validity: certificate validity in days
    @param force: overwrite existing certificate
    """
    logger.debug("Build and sign certificate")
    cert_file = sanitise_path(name, ".crt.pem")

    write_mode = "wb" if force else "xb"

    try:
        with cert_file.open(write_mode) as file:
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

            file.write(cert_pem)
            logger.info("Saved certificate '%s'", cert_file.name)

            logger.info("Your certificate:\n")
            print(cert_pem.decode("utf-8"))
    except FileExistsError:
        logger.error(
            "Re-using existing certificate '%s'. (%s)",
            cert_file.name,
            FORCE_HINT,
        )


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Helper script for creating Certificate Signing Requests (CSR)",
)
def cli():
    # pylint: disable=missing-function-docstring
    pass


@cli.command()
@click.option("--settings-file", "-f", type=str, default="settings.yaml")
def create_settings_file(settings_file: str | Path):
    """
    Create settings file
    """
    logger.debug("Run CLI create_settings_file")
    new_settings = {
        "nameoid": {
            "COUNTRY_NAME": "NL",
            "STATE_OR_PROVINCE_NAME": "Noord-Holland",
            "LOCALITY_NAME": "Amsterdam",
            "ORGANIZATION_NAME": "Foo Bar Ltd.",
            "ORGANIZATIONAL_UNIT": "Department of Redundancy Department",
        }
    }
    with settings_file.open("w") as file:
        safe_dump(new_settings, file)


@cli.command()
def debug():
    """
    Debug function with static domains
    """
    logger.debug("Run CLI debug")
    san = [
        x509.DNSName("example.org"),
        x509.DNSName("*.example.org"),
        x509.DNSName("example.net"),
    ]
    create_csr("test", san, "ec", True)
    create_certificate("test", san, "ec", 10, True)


@cli.command()
def interactive():
    """
    Create CSR interactively
    """
    logger.debug("Run CLI interactive")
    common_name = click.prompt("What is the primary domain?", type=str)
    while not validate_dnsname(common_name):
        common_name = click.prompt("What is the primary domain?", type=str)
    key_type = click.prompt("What type of key to use? ('ec' or 'rsa')", default="ec")
    self_signed = click.prompt(
        "Do you want to create self-signed certificate?", type=bool, default=False
    )

    more_altnames = True
    altnames = [x509.DNSName(common_name)]
    while more_altnames:
        this_name = click.prompt(
            "Please enter any additional names", type=str, default=""
        )
        if not this_name:
            more_altnames = False
        else:
            if validate_dnsname(this_name):
                altnames.append(x509.DNSName(this_name))

    if not create_csr(common_name, altnames, key_type):
        overwrite = click.prompt(
            "CSR for this domain already exists, overwrite it?",
            type=bool,
            default=False,
        )
        if overwrite:
            create_csr(common_name, altnames, key_type, overwrite)

    if self_signed:
        validity = click.prompt(
            "How long do you want the certificate to be valid for?",
            type=int,
            default=365,
        )
        if not create_certificate(common_name, altnames, key_type, validity):
            overwrite = click.prompt(
                "Certificate for this domain already exists, overwrite it?",
                type=bool,
                default=False,
            )
            if overwrite:
                create_certificate(common_name, altnames, key_type, validity, overwrite)


HELP_TEXT_DOMAIN = (
    "Domain to create a CSR for. Can be passed multiple times, "
    "the first entry will be the primary domain"
)
HELP_TEXT_TYPE = "Type of key to generate. 'rsa' or 'ec', defaults to 'ec'"
HELP_TEXT_SIGN = "Create self-signed certificate?"


@cli.command()
@click.option("--domain", "-d", multiple=True, required=True, help=HELP_TEXT_DOMAIN)
@click.option("--type", "-t", "key_type", default="ec", help=HELP_TEXT_TYPE)
@click.option("--sign", "-s", is_flag=True, type=bool, help=HELP_TEXT_SIGN)
@click.option(
    "--validity",
    "-v",
    default=365,
    type=int,
    help="Length of certificate validity, in days",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    type=bool,
    help="Overwrite existing CSR and certificate, if present",
    default=False,
)
def create(domain, key_type, sign, validity, force):
    """
    Pass domains to create without going interactive
    """
    logger.debug("Run CLI create")
    common_name = domain[0].strip("'")
    altnames = []
    error = False

    global settings
    settings = load_settings()

    for name in domain:
        if re.search(domain_regex, name):
            altnames.append(x509.DNSName(name))
        else:
            logger.error("Domain '%s' is invalid!", name)
            error = True
    if error:
        sys.exit(1)

    create_csr(common_name, altnames, key_type, force)

    if sign:
        create_certificate(common_name, altnames, key_type, validity, force)


if __name__ == "__main__":
    cli()
