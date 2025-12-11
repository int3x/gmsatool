from ldap3.protocol.microsoft import security_descriptor_control
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from rich import box
from rich.console import Console
from rich.table import Table

from gmsatool.protocols.ldap import get_entry, sid_to_samaccountname, LDAPNoResultsError
from gmsatool.helpers.common import logger, bcolors


class GMSAAutomator:
    def __init__(self, domain, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.ldap_session = ldap_session

    def automate_enumeration(self):
        attributes = ["sAMAccountName", "msDS-GroupMSAMembership", "nTSecurityDescriptor"]
        # results = get_entry(self.ldap_session, self.dn, search_filter="(objectClass=msDS-GroupManagedServiceAccount)", attributes=attributes, controls=security_descriptor_control(sdflags=0x07))

        # for result in results:
        #     sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["nTSecurityDescriptor"])
        #     gmsa_sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["msDS-GroupMSAMembership"])
