from ldap3.protocol.microsoft import security_descriptor_control
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from rich import box
from rich.console import Console
from rich.table import Table

from gmsatool.protocols.ldap import get_entry, sid_to_samaccountname, LDAPNoResultsError
from gmsatool.helpers.common import logger, bcolors


class GMSAEnumerator:
    def __init__(self, domain, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.ldap_session = ldap_session

    def get_gmsa_accounts(self):
        try:
            attributes = ["sAMAccountName", "msDS-GroupMSAMembership", "nTSecurityDescriptor"]
            results = get_entry(self.ldap_session, self.dn, search_filter="(objectClass=msDS-GroupManagedServiceAccount)", attributes=attributes, controls=security_descriptor_control(sdflags=0x07))
        except LDAPNoResultsError as e:
            logger.error(f"{bcolors.FAIL}[!] {e}{bcolors.ENDC}")
            return None

        read_privileges = []
        modify_privileges = []

        for result in results:
            if result["attributes"]["msDS-GroupMSAMembership"]:
                gmsa_sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["msDS-GroupMSAMembership"])
                for ace in gmsa_sd.Dacl.aces:
                    principal, principal_dn, principal_type = sid_to_samaccountname(self.ldap_session, self.dn, ace.Sid)
                    read_privileges.append({"gmsa": result["attributes"]["sAMAccountName"], "principal": principal, "principal_dn": principal_dn, "principal_type": principal_type})

            sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["nTSecurityDescriptor"])
            for ace in sd.Dacl.aces:
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c651f64d-5e92-4d12-9011-e6811ed306aa
                if hasattr(ace, "ObjectType") and str(ace.ObjectType) == "888eedd6-ce04-df40-b462-b8a50e41ba38":
                    principal, principal_dn, principal_type = sid_to_samaccountname(self.ldap_session, self.dn, ace.Sid)
                    modify_privileges.append({"gmsa": result["attributes"]["sAMAccountName"], "principal": principal, "principal_dn": principal_dn, "principal_type": principal_type})

        return read_privileges, modify_privileges

    def display(self, read_privileges, modify_privileges):
        console = Console()

        if read_privileges:
            gmsa_read_principals = Table(box=box.ROUNDED, title="[bold bright_yellow]Read privileges[/bold bright_yellow]", title_justify="left")
            gmsa_read_principals.add_column("[bold bright_cyan]gMSA account[/bold bright_cyan]")
            gmsa_read_principals.add_column("[bold bright_cyan]Principal with ReadGMSApassword[/bold bright_cyan]")
            gmsa_read_principals.add_column("[bold bright_cyan]Principal Type[/bold bright_cyan]")

            for entry in read_privileges:
                principal_type = "Group" if "group" in entry["principal_type"] else "User"
                gmsa_read_principals.add_row(entry["gmsa"], entry["principal"], principal_type)

            console.print(gmsa_read_principals)

        if modify_privileges:
            gmsa_modify_principals = Table(box=box.ROUNDED, title="\n[bold bright_yellow]Modify privileges[/bold bright_yellow]", title_justify="left")
            gmsa_modify_principals.add_column("[bold bright_cyan]gMSA account[/bold bright_cyan]")
            gmsa_modify_principals.add_column("[bold bright_cyan]Access Manager[/bold bright_cyan]")
            gmsa_modify_principals.add_column("[bold bright_cyan]Principal Type[/bold bright_cyan]")

            for entry in modify_privileges:
                principal_type = "Group" if "group" in entry["principal_type"] else "User"
                gmsa_modify_principals.add_row(entry["gmsa"], entry["principal"], principal_type)

            console.print(gmsa_modify_principals)
