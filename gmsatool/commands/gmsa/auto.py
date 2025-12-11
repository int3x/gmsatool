from ldap3.protocol.microsoft import security_descriptor_control
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from rich import box
from rich.console import Console
from rich.table import Table

from gmsatool.commands.enum.find_gmsa import GMSAEnumerator
from gmsatool.commands.gmsa.read_password import GMSAReader
from gmsatool.commands.gmsa.access import GMSAMembership
from gmsatool.protocols.ldap import get_entry, sid_to_samaccountname, LDAPNoResultsError
from gmsatool.helpers.common import logger, bcolors


class GMSAAutomator:
    def __init__(self, domain, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.ldap_session = ldap_session

    def automate_enumeration(self):
        return
