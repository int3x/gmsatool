import hashlib
import math
from base64 import b64encode
from binascii import hexlify

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Cryptodome.Hash import MD4
from rich import print
from rich.panel import Panel

from gmsatool.protocols.ldap import get_entry
from gmsatool.helpers.structure import Structure
from gmsatool.helpers.common import logger, bcolors


def _nfold(n_bits, data):
    k_bits = len(data) * 8
    lcm_bits = (n_bits * k_bits) // math.gcd(n_bits, k_bits)
    def getbit(d, i): return (d[i // 8] >> (7 - (i % 8))) & 1
    buf = bytearray(lcm_bits // 8)
    for i in range(lcm_bits):
        copy = i // k_bits
        src_bit = (i % k_bits - 13 * copy) % k_bits
        buf[i // 8] |= getbit(data, src_bit) << (7 - (i % 8))
    n_bytes = n_bits // 8
    result = bytearray(n_bytes)
    for i in range(len(buf) - 1, -1, -1):
        pos = i % n_bytes
        acc = result[pos] + buf[i]
        result[pos] = acc & 0xFF
        carry = acc >> 8
        j = pos
        while carry:
            j = (j - 1) % n_bytes
            acc = result[j] + carry
            result[j] = acc & 0xFF
            carry = acc >> 8
    return bytes(result)


def _aes_string_to_key(password_bytes, salt_bytes, keysize, iterations=4096):
    tkey = hashlib.pbkdf2_hmac('sha1', password_bytes, salt_bytes, iterations, keysize)
    k = _nfold(128, b"kerberos")
    result = b""
    while len(result) < keysize:
        cipher = Cipher(algorithms.AES(tkey), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        k = enc.update(k) + enc.finalize()
        result += k
    return result[:keysize]


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

    def calc_aes_keys(self, samaccountname, domain):
        password_utf8 = self["CurrentPassword"].decode("utf-16-le", "replace").encode("utf-8")
        account = samaccountname.rstrip('$').lower() if samaccountname.endswith("$") else samaccountname.lower()
        salt = (domain.upper() + "host" + account + "." + domain.lower()).encode("utf-8")
        aes128 = _aes_string_to_key(password_utf8, salt, 16)
        aes256 = _aes_string_to_key(password_utf8, salt, 32)
        return aes128.hex(), aes256.hex()


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
            aes128, aes256 = blob.calc_aes_keys(self.target, self.domain)
            print(Panel(aes128, title="gMSA aes128-cts-hmac-sha1-96", title_align="left"))
            print(Panel(aes256, title="gMSA aes256-cts-hmac-sha1-96", title_align="left"))
