import logging
from typing import Annotated, Optional

import cyclopts
from cyclopts import Parameter

from gmsatool.commands.enum.find_gmsa import GMSAEnumerator
from gmsatool.commands.gmsa.read_password import GMSAReader
from gmsatool.commands.gmsa.access import GMSAMembership
from gmsatool.commands.gmsa.auto import GMSAAutomator
from gmsatool.protocols.ldap import get_ldap_session
from gmsatool.helpers.common import logger, bcolors


Domain = Annotated[str, Parameter(name=["--domain", "-d"], help="The domain name")]
DC = Annotated[Optional[str], Parameter(name="--dc", help="The target domain controller (IP or FQDN). If omitted, defaults to the domain FQDN")]
Username = Annotated[Optional[str], Parameter(name=["--username", "-u"], help="The username")]
Password = Annotated[Optional[str], Parameter(name=["--password", "-p"], help="The password")]
Hash = Annotated[Optional[str], Parameter(name=["--hash", "-H"], help="The NT hash for the domain account")]
Kerberos = Annotated[bool, Parameter(name="-k", help="Use Kerberos authentication. Default TGT location is /tmp/krb5cc_$(id -u)")]
LDAPS = Annotated[bool, Parameter(name="--ldaps", help="Use LDAPS (port 636)", negative="")]
Verbose = Annotated[bool, Parameter(name=["--verbose", "-v"], help="Enable verbose output", negative="")]


app = cyclopts.App()
enum_app = cyclopts.App(name="enum", help="Enumeration Subcommands")
gmsa_app = cyclopts.App(name="gmsa", help="gMSA Subcommands")

app.command(enum_app)
app.command(gmsa_app)


def validate_auth_params(username, password, hash):
    """Validate authentication parameter combinations"""
    if password is not None and hash is not None:
        raise ValueError("Cannot use both --password and --hash simultaneously")

    if username is not None and password is None and hash is None:
        raise ValueError("When --username is specified, either --password or --hash must be provided")


def setup_and_connect(domain, dc, username, password, hash, kerberos, ldaps, verbose):
    """Setup logging, process args, and return LDAP session"""
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if password is None and hash is not None:
        password = "0" * 32 + ":" + hash

    dc = dc if dc else domain

    return get_ldap_session(domain, dc, ldaps, username, password, kerberos, all_info=True)


@enum_app.command
def find_gmsa(
    domain: Domain,
    dc: DC = None,
    username: Username = None,
    password: Password = None,
    hash: Hash = None,
    kerberos: Kerberos = False,
    ldaps: LDAPS = False,
    verbose: Verbose = False,
):
    """Find gMSA accounts, users with password read access, and users who can modify that access"""
    validate_auth_params(username, password, hash)
    ldap_session = setup_and_connect(domain, dc, username, password, hash, kerberos, ldaps, verbose)
    gmsa_enumerator = GMSAEnumerator(domain, ldap_session)
    read_privileges, modify_privileges = gmsa_enumerator.get_gmsa_accounts()
    gmsa_enumerator.display(read_privileges, modify_privileges)


@gmsa_app.command
def read_password(
    domain: Domain,
    target: Annotated[str, Parameter(name="--target", help="The target gMSA account")],
    dc: DC = None,
    username: Username = None,
    password: Password = None,
    hash: Hash = None,
    kerberos: Kerberos = False,
    ldaps: LDAPS = False,
    verbose: Verbose = False,
):
    """Read gMSA password of a target account"""
    validate_auth_params(username, password, hash)
    ldap_session = setup_and_connect(domain, dc, username, password, hash, kerberos, ldaps, verbose)
    gmsa_reader = GMSAReader(domain, target, ldap_session)
    gmsa_reader.read_gmsa_password()


@gmsa_app.command
def access(
    domain: Domain,
    target: Annotated[str, Parameter(name="--target", help="The target gMSA account")],
    principal: Annotated[str, Parameter(name="--principal", help="The account designated for privilege modification")],
    dc: DC = None,
    username: Username = None,
    password: Password = None,
    hash: Hash = None,
    kerberos: Kerberos = False,
    ldaps: LDAPS = False,
    verbose: Verbose = False,
):
    """Grant or deny gMSA password read privilege to a principal"""
    logger.debug(f"{bcolors.WARNING}\n[*] The feature to remove gMSA password read access has not been implemented!{bcolors.ENDC}")

    validate_auth_params(username, password, hash)
    ldap_session = setup_and_connect(domain, dc, username, password, hash, kerberos, ldaps, verbose)
    gmsa_enumerator = GMSAMembership(domain, target, principal, ldap_session)
    gmsa_enumerator.add_readgmsapassword_access()


@gmsa_app.command
def auto(
    domain: Domain,
    dc: DC = None,
    username: Username = None,
    password: Password = None,
    hash: Hash = None,
    kerberos: Kerberos = False,
    ldaps: LDAPS = False,
    verbose: Verbose = False,
):
    """Automated enumeration and abuse of gMSA privileges (experimental)"""
    logger.error(f"{bcolors.FAIL}[!] Feature not implemented!{bcolors.ENDC}")
    validate_auth_params(username, password, hash)
    ldap_session = setup_and_connect(domain, dc, username, password, hash, kerberos, ldaps, verbose)
    gmsa_automator = GMSAAutomator(domain, ldap_session)
    gmsa_automator.automate_enumeration()


if __name__ == "__main__":
    app()
