from ldap3.protocol.microsoft import security_descriptor_control
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from gmsatool.protocols.ldap import get_entry


class GMSAAutomator:
    def __init__(self, domain, target, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.target = target
        self.ldap_session = ldap_session

    def automate_enumeration(self):
        attributes = ["sAMAccountName", "msDS-GroupMSAMembership", "nTSecurityDescriptor"]
        result = get_entry(self.ldap_session, self.dn, search_filter="(objectClass=msDS-GroupManagedServiceAccount)", attributes=attributes, controls=security_descriptor_control(sdflags=0x07))
        sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["nTSecurityDescriptor"])
        gmsa_sd = SECURITY_DESCRIPTOR.from_bytes(result["attributes"]["msDS-GroupMSAMembership"])
