from ldap3 import Server, Connection, SASL, NTLM, KERBEROS, MODIFY_REPLACE, ALL_ATTRIBUTES, SCHEMA, ALL, TLS_CHANNEL_BINDING, ENCRYPT

from gmsatool.helpers.common import logger


class LDAPNoResultsError(Exception):
    pass


def get_ldap_session(domain, dc, ldaps, username, password, kerberos=False, all_info=False):
    if ldaps is True:
        server = Server(f"ldaps://{dc}:636", port=636, use_ssl=True, get_info=SCHEMA if all_info is False else ALL)
    else:
        server = Server(f"ldap://{dc}:389", port=389, use_ssl=False, get_info=SCHEMA if all_info is False else ALL)

    if kerberos is False:
        if ldaps is True:
            logger.debug(f"[*] Authenticating to ldaps://{dc}:636 with NTLM")
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True, raise_exceptions=True, channel_binding=TLS_CHANNEL_BINDING)
        else:
            logger.debug(f"[*] Authenticating to ldap://{dc}:389 with NTLM")
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True, raise_exceptions=True, session_security=ENCRYPT)
    else:
        if ldaps is True:
            logger.debug(f"[*] Authenticating to ldaps://{dc}:636 with Kerberos")
            ldap_session = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True, raise_exceptions=True)
        else:
            logger.debug(f"[*] Authenticating to ldap://{dc}:389 with Kerberos")
            ldap_session = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True, raise_exceptions=True, session_security=ENCRYPT)
    return ldap_session


def get_entry(ldap_session, dn, search_filter="(objectClass=*)", attributes=ALL_ATTRIBUTES, get_operational_attributes=False, controls=None):
    entries = []
    logger.debug(f"[*] Querying {attributes} attribute on {dn} with search filter {search_filter}")
    ldap_session.search(search_base=dn, search_filter=search_filter, attributes=attributes, get_operational_attributes=get_operational_attributes, controls=controls)

    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)

    if len(entries) == 0:
        raise LDAPNoResultsError(f"LDAP query for '{dn}' with search filter {search_filter} did not return any results")
    return entries


def modify_attribute(ldap_session, dn, attribute, new_value):
    logger.debug(f"[*] Attempting to set the attribute {attribute} for {dn} to {new_value}")
    ldap_session.modify(dn, {attribute: [(MODIFY_REPLACE, [new_value])]})


def sid_to_samaccountname(ldap_session, dn, sid):
    logger.debug(f"[*] Querying sAMAccountName attribute on {dn} with search filter (objectSid={sid})")
    ldap_session.search(search_base=dn, search_filter=f"(objectSid={sid})", attributes=["sAMAccountName", "objectClass"], size_limit=1)

    entries = []
    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)
    if len(entries) == 0:
        raise LDAPNoResultsError(f"LDAP query for '{dn}' with search filter (objectSid={sid}) did not return any results")
    return entries[0]["attributes"]["sAMAccountName"], entries[0]["dn"], entries[0]["attributes"]["objectClass"]


def samaccountname_to_sid(ldap_session, dn, samaccountname):
    logger.debug(f"[*] Querying objectSid attribute on {dn} with search filter (sAMAccountName={samaccountname})")
    ldap_session.search(search_base=dn, search_filter=f"(sAMAccountName={samaccountname})", attributes=["objectSid"], size_limit=1)

    entries = []
    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)
    if len(entries) == 0:
        raise LDAPNoResultsError(f"LDAP query for '{dn}' with search filter (sAMAccountName={samaccountname}) did not return any results")
    return entries[0]["attributes"]["objectSid"]


def check_group_membership(ldap_session, dn, username, group_dn):
    logger.debug(f"[*] Querying memberOf attribute on {dn} with search filter (sAMAccountName={username})")
    ldap_session.search(search_base=dn, search_filter=f"(&(sAMAccountName={username})(memberOf:1.2.840.113556.1.4.1941:={group_dn}))", attributes=["distinguishedName"])

    entries = []
    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)
    if len(entries) == 0:
        return False
    return True
