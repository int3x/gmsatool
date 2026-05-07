from ldap3.protocol.microsoft import security_descriptor_control
from rich import box
from rich.console import Console
from rich.table import Table
from winacl.dtyp.ace import ACCESS_MASK, ADS_ACCESS_MASK, STANDARD_ACCESS_MASK, ACEType
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.sid import well_known_sids_sid_name_map

from gmsatool.helpers.common import bcolors, logger
from gmsatool.protocols.ldap import LDAPNoResultsError, get_entry, sid_to_samaccountname

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c651f64d-5e92-4d12-9011-e6811ed306aa
GROUP_MSA_MEMBERSHIP_GUID = "888eedd6-ce04-df40-b462-b8a50e41ba38"

DENY_ACE_TYPES = {
    ACEType.ACCESS_DENIED_ACE_TYPE,
    ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
}


def ace_grants_gmsa_write(ace):
    if ace.AceType in DENY_ACE_TYPES:
        return False

    mask = ace.Mask

    if mask & (ACCESS_MASK.GENERIC_ALL | ACCESS_MASK.GENERIC_WRITE):
        return True

    if mask & (ADS_ACCESS_MASK.GENERIC_ALL | ADS_ACCESS_MASK.GENERIC_WRITE | ADS_ACCESS_MASK.WRITE_DACL | ADS_ACCESS_MASK.WRITE_OWNER):
        return True

    if mask & ADS_ACCESS_MASK.WRITE_PROP:
        object_type = str(getattr(ace, "ObjectType", None))
        if object_type == GROUP_MSA_MEMBERSHIP_GUID or not hasattr(ace, "ObjectType"):
            return True

    return False


class GMSAEnumerator:
    def __init__(self, domain, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.ldap_session = ldap_session

    def get_gmsa_accounts(self):
        try:
            attributes = ["sAMAccountName", "msDS-GroupMSAMembership", "nTSecurityDescriptor"]
            results = get_entry(
                self.ldap_session,
                self.dn,
                search_filter="(objectClass=msDS-GroupManagedServiceAccount)",
                attributes=attributes,
                controls=security_descriptor_control(sdflags=0x07),
            )
        except LDAPNoResultsError as e:
            logger.error(f"{bcolors.FAIL}[!] {e}{bcolors.ENDC}")
            return None, None

        read_privileges = []
        modify_privileges = []

        for result in results:
            if result["attributes"]["msDS-GroupMSAMembership"]:
                gmsa_sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["msDS-GroupMSAMembership"])
                for ace in gmsa_sd.Dacl.aces:
                    sid_str = str(ace.Sid)
                    if sid_str in well_known_sids_sid_name_map:
                        continue
                    principal, principal_dn, principal_type = sid_to_samaccountname(self.ldap_session, self.dn, ace.Sid)
                    read_privileges.append(
                        {
                            "gmsa": result["attributes"]["sAMAccountName"],
                            "principal": principal,
                            "principal_dn": principal_dn,
                            "principal_type": principal_type,
                        }
                    )
            else:
                read_privileges.append(
                    {
                        "gmsa": result["attributes"]["sAMAccountName"],
                        "principal": "Domain Admins",
                        "principal_dn": f"CN=Domain Admins,CN=Users,{self.dn}",
                        "principal_type": "group",
                    }
                )

            sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["nTSecurityDescriptor"])
            for ace in sd.Dacl.aces:
                sid_str = str(ace.Sid)
                if sid_str in well_known_sids_sid_name_map:
                    continue
                if ace_grants_gmsa_write(ace):
                    principal, principal_dn, principal_type = sid_to_samaccountname(self.ldap_session, self.dn, ace.Sid)
                    modify_privileges.append(
                        {
                            "gmsa": result["attributes"]["sAMAccountName"],
                            "principal": principal,
                            "principal_dn": principal_dn,
                            "principal_type": principal_type,
                        }
                    )

        return read_privileges, modify_privileges

    def display(self, read_privileges, modify_privileges):
        console = Console()

        if read_privileges:
            gmsa_read_principals = Table(box=box.ROUNDED, title="[bold bright_yellow]Read privileges[/bold bright_yellow]", title_justify="left")
            gmsa_read_principals.add_column("[bold bright_cyan]gMSA account[/bold bright_cyan]")
            gmsa_read_principals.add_column("[bold bright_cyan]Principal with ReadGMSApassword[/bold bright_cyan]")
            gmsa_read_principals.add_column("[bold bright_cyan]Principal Type[/bold bright_cyan]")

            for entry in read_privileges:
                principal_type = "Group" if any(x in entry["principal_type"] for x in ("group", "well-known")) else "User"
                gmsa_read_principals.add_row(entry["gmsa"], entry["principal"], principal_type)

            console.print(gmsa_read_principals)

        if modify_privileges:
            gmsa_modify_principals = Table(
                box=box.ROUNDED, title="\n[bold bright_yellow]Modify privileges[/bold bright_yellow]", title_justify="left"
            )
            gmsa_modify_principals.add_column("[bold bright_cyan]gMSA account[/bold bright_cyan]")
            gmsa_modify_principals.add_column("[bold bright_cyan]Access Manager[/bold bright_cyan]")
            gmsa_modify_principals.add_column("[bold bright_cyan]Principal Type[/bold bright_cyan]")

            for entry in modify_privileges:
                principal_type = "Group" if "group" in entry["principal_type"] else "User"
                gmsa_modify_principals.add_row(entry["gmsa"], entry["principal"], principal_type)

            console.print(gmsa_modify_principals)
