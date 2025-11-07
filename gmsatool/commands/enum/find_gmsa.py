from ldap3.protocol.microsoft import security_descriptor_control
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from rich import box
from rich.console import Console
from rich.table import Table

from gmsatool.protocols.ldap import get_entry, sid_to_samaccountname
from gmsatool.helpers.common import logger, bcolors


class GMSAEnumerator:
    def __init__(self, domain, target, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.target = target
        self.ldap_session = ldap_session

    def get_gmsa_accounts(self):
        attributes = ["sAMAccountName", "msDS-GroupMSAMembership", "nTSecurityDescriptor"]
        result = get_entry(self.ldap_session, self.dn, search_filter="(objectClass=msDS-GroupManagedServiceAccount)", attributes=attributes, controls=security_descriptor_control(sdflags=0x07))
        sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["nTSecurityDescriptor"])
        gmsa_sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["msDS-GroupMSAMembership"])

        gmsa_read_principals = Table(box=box.ROUNDED, title="[bold bright_yellow]Read privileges[/bold bright_yellow]", title_justify="left")
        gmsa_read_principals.add_column("[bold bright_cyan]gMSA account[/bold bright_cyan]")
        gmsa_read_principals.add_column("[bold bright_cyan]Principles with ReadGMSApassword privilege[/bold bright_cyan]")

        for ace in gmsa_sd.Dacl.aces:
            gmsa_read_principals.add_row(result["attributes"]["sAMAccountName"], sid_to_samaccountname(self.ldap_session, self.dn, ace.Sid))

        gmsa_modify_principals = Table(box=box.ROUNDED, title="\n[bold bright_yellow]Modify privileges[/bold bright_yellow]", title_justify="left")
        gmsa_modify_principals.add_column("[bold bright_cyan]gMSA account[/bold bright_cyan]")
        gmsa_modify_principals.add_column("[bold bright_cyan]Can modify ReadGMSApassword privilege[/bold bright_cyan]")

        for ace in sd.Dacl.aces:
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c651f64d-5e92-4d12-9011-e6811ed306aa
            if hasattr(ace, "ObjectType") and str(ace.ObjectType) == "888eedd6-ce04-df40-b462-b8a50e41ba38":
                gmsa_modify_principals.add_row(result["attributes"]["sAMAccountName"], sid_to_samaccountname(self.ldap_session, self.dn, ace.Sid))

        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] gMSA accounts found:{bcolors.ENDC}")

        console = Console()
        console.print(gmsa_read_principals)
        console.print(gmsa_modify_principals)
