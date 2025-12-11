from ldap3.protocol.microsoft import security_descriptor_control
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from rich import box
from rich.console import Console
from rich.table import Table

from gmsatool.protocols.ldap import get_entry, modify_attribute, sid_to_samaccountname, samaccountname_to_sid
from gmsatool.helpers.common import logger, bcolors


class GMSAMembership:
    def __init__(self, domain, target, principal, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.target = target
        self.principal = principal
        self.ldap_session = ldap_session

    def add_readgmsapassword_access(self):
        attributes = ["distinguishedName", "msDS-GroupMSAMembership"]
        filter = f"(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={self.target}))"
        result = get_entry(self.ldap_session, self.dn, search_filter=filter, attributes=attributes, controls=security_descriptor_control(sdflags=0x07))

        target_dn = result[0]["attributes"]["distinguishedName"]

        current_value = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["msDS-GroupMSAMembership"]).to_sddl()
        new_value = current_value + f"(A;;0xf01ff;;;{samaccountname_to_sid(self.ldap_session, self.dn, self.principal)})"
        new_value = SECURITY_DESCRIPTOR.from_sddl(new_value).to_bytes()
        modify_attribute(self.ldap_session, target_dn, "msDS-GroupMSAMembership", new_value)
        logger.info(f"{bcolors.OKGREEN}[+] msDS-GroupMSAMembership successfully updated for {target_dn}{bcolors.ENDC}")

        result = get_entry(self.ldap_session, self.dn, search_filter="(sAMAccountName={self.target})", attributes=["msDS-GroupMSAMembership"], controls=security_descriptor_control(sdflags=0x07))
        gmsa_sd = SECURITY_DESCRIPTOR.from_bytes(result[0]["attributes"]["msDS-GroupMSAMembership"])

        gmsa_read_principals = Table(box=box.ROUNDED, title="[bold bright_yellow]Read privileges[/bold bright_yellow]", title_justify="left")
        gmsa_read_principals.add_column("[bold bright_cyan]gMSA account[/bold bright_cyan]")
        gmsa_read_principals.add_column("[bold bright_cyan]Principles with ReadGMSApassword privilege[/bold bright_cyan]")

        for ace in gmsa_sd.Dacl.aces:
            gmsa_read_principals.add_row(result["attributes"]["sAMAccountName"], sid_to_samaccountname(self.ldap_session, self.dn, ace.Sid))

        console = Console()
        console.print(gmsa_read_principals)
