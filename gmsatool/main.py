import typer
import logging
import traceback

from typing_extensions import Annotated
from gmsatool.commands.enum.find_gmsa import GMSAEnumerator
from gmsatool.commands.gmsa.read_password import GMSAReader
from gmsatool.commands.gmsa.access import GMSAMembership
from gmsatool.commands.gmsa.auto import GMSAAutomator
from gmsatool.protocols.ldap import get_ldap_session
from gmsatool.helpers.common import logger, bcolors


app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, add_completion=False)
enum_app = typer.Typer()
gmsa_app = typer.Typer()

app.add_typer(enum_app, name="enum", help="Subcommands for enumeration")
app.add_typer(gmsa_app, name="gmsa", help="Subcommands for reading gMSA password and access manipulation")


def set_verbosity(value):
    if value:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


@enum_app.command(help="Find gMSA accounts, users with password read access, and users who can modify that access")
def find_gmsa(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain FQDN")],
    target: Annotated[str, typer.Option("--target", help="The target gMSA account (opional)")] = None,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Default TGT location is /tmp/krb5cc_1000")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output", callback=set_verbosity)] = False,
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = "0" * 32 + ":" + hash
        if dc is None:
            dc = domain

        logger.debug("[*] Attempting to obtain an LDAP session...")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos, all_info=True)
        logger.debug(f"{bcolors.OKGREEN}[*] Session establised!{bcolors.ENDC}")
        gmsa_enumerator = GMSAEnumerator(domain, target, ldap_session)
        gmsa_enumerator.get_gmsa_accounts()

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running enum command{bcolors.ENDC}")
        traceback.print_exc()


@gmsa_app.command(help="Read gMSA password of a target account")
def read_password(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    target: Annotated[str, typer.Option("--target", help="The target gMSA account")],
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Default TGT location is /tmp/krb5cc_1000")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0,
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = "0" * 32 + ":" + hash
        if dc is None:
            dc = domain

        logger.debug("[*] Attempting to obtain an LDAP session...")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos, all_info=True)
        logger.debug(f"{bcolors.OKGREEN}[*] Session establised!{bcolors.ENDC}")

        logger.info(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] Principals allowed to read the gMSA account for {target}:{bcolors.ENDC}")

        gmsa_reader = GMSAReader(domain, target, ldap_session)
        gmsa_reader.read_gmsa_password()

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running the command{bcolors.ENDC}")
        traceback.print_exc()


@gmsa_app.command(help="Grant or deny gMSA password read privilege to a principal")
def access(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    target: Annotated[str, typer.Option("--target", help="The target gMSA account")],
    principal: Annotated[str, typer.Option("--principal", help="The account designated for privilege modification")],
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Default TGT location is /tmp/krb5cc_1000")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0,
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = "0" * 32 + ":" + hash
        if dc is None:
            dc = domain

        logger.info(f"{bcolors.WARNING}\n[!] The feature to remove gMSA password read access has not been implemented!{bcolors.ENDC}")

        logger.debug("[*] Attempting to obtain an LDAP session...")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos, all_info=True)
        logger.debug(f"{bcolors.OKGREEN}[*] Session establised!{bcolors.ENDC}")
        gmsa_enumerator = GMSAMembership(domain, target, principal, ldap_session)
        gmsa_enumerator.add_readgmsapassword_access()

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running the command{bcolors.ENDC}")
        traceback.print_exc()


@gmsa_app.command(help="Automated enumeration and abuse of gMSA privileges (experimental)")
def auto(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Default TGT location is /tmp/krb5cc_1000")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0,
):
    logger.error(f"{bcolors.FAIL}[!] Feature not implemented!{bcolors.ENDC}")


if __name__ == "__main__":
    app()
