"""
AD Connector - Modulo connessione Active Directory via LDAP
Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

import ssl
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from ldap3 import (
    Server, Connection, ALL, NTLM, SIMPLE, SASL,
    SUBTREE, BASE, LEVEL, ALL_ATTRIBUTES,
    Tls, MODIFY_REPLACE
)
from ldap3.core.exceptions import (
    LDAPBindError, LDAPSocketOpenError,
    LDAPInvalidCredentialsResult, LDAPException
)


@dataclass
class ADConnectionInfo:
    """Informazioni sulla connessione AD"""
    server: str
    domain: str
    base_dn: str
    connected: bool = False
    ssl: bool = False
    user: str = ""
    error: str = ""


class ADConnector:
    """
    Gestisce la connessione ad Active Directory via LDAP.
    Supporta connessioni LDAP (389) e LDAPS (636).
    """

    def __init__(
        self,
        server: str,
        username: str,
        password: str,
        domain: Optional[str] = None,
        use_ssl: bool = True,
        port: Optional[int] = None,
        timeout: int = 30,
        validate_cert: bool = True
    ):
        """
        Inizializza il connettore AD.

        Args:
            server: Hostname o IP del Domain Controller
            username: Username (può essere user@domain o DOMAIN\\user)
            password: Password
            domain: Nome dominio (opzionale, estratto da username)
            use_ssl: Usa LDAPS (porta 636) invece di LDAP (389)
            port: Porta personalizzata (default: 636 se SSL, 389 altrimenti)
            timeout: Timeout connessione in secondi
            validate_cert: Valida certificato SSL
        """
        self.server_address = server
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.validate_cert = validate_cert

        # Determina porta
        if port:
            self.port = port
        else:
            self.port = 636 if use_ssl else 389

        # Estrai dominio da username se non specificato
        if domain:
            self.domain = domain
        elif "@" in username:
            self.domain = username.split("@")[1]
        elif "\\" in username:
            self.domain = username.split("\\")[0]
        else:
            self.domain = ""

        # Costruisci Base DN dal dominio
        self.base_dn = self._domain_to_dn(self.domain)

        # Oggetti connessione
        self._server: Optional[Server] = None
        self._connection: Optional[Connection] = None
        self._connected = False

    def _domain_to_dn(self, domain: str) -> str:
        """Converte nome dominio in Distinguished Name"""
        if not domain:
            return ""
        parts = domain.lower().split(".")
        return ",".join(f"DC={part}" for part in parts)

    def connect(self) -> ADConnectionInfo:
        """
        Stabilisce la connessione ad Active Directory.

        Returns:
            ADConnectionInfo con dettagli connessione
        """
        info = ADConnectionInfo(
            server=self.server_address,
            domain=self.domain,
            base_dn=self.base_dn,
            ssl=self.use_ssl,
            user=self.username
        )

        try:
            # Configura TLS se necessario
            tls_config = None
            if self.use_ssl:
                if self.validate_cert:
                    tls_config = Tls(validate=ssl.CERT_REQUIRED)
                else:
                    tls_config = Tls(validate=ssl.CERT_NONE)

            # Crea server
            self._server = Server(
                self.server_address,
                port=self.port,
                use_ssl=self.use_ssl,
                get_info=ALL,
                tls=tls_config,
                connect_timeout=self.timeout
            )

            # Determina formato username per autenticazione
            if "@" in self.username:
                # user@domain.com - usa SIMPLE bind
                auth_user = self.username
                auth_method = SIMPLE
            elif "\\" in self.username:
                # DOMAIN\\user - usa NTLM
                auth_user = self.username
                auth_method = NTLM
            else:
                # Aggiungi dominio se disponibile
                if self.domain:
                    auth_user = f"{self.username}@{self.domain}"
                    auth_method = SIMPLE
                else:
                    auth_user = self.username
                    auth_method = SIMPLE

            # Crea connessione
            self._connection = Connection(
                self._server,
                user=auth_user,
                password=self.password,
                authentication=auth_method,
                auto_bind=True,
                receive_timeout=self.timeout
            )

            self._connected = True
            info.connected = True

            # Aggiorna base_dn dal server se vuoto
            if not self.base_dn and self._server.info:
                naming_contexts = self._server.info.naming_contexts
                if naming_contexts:
                    self.base_dn = naming_contexts[0]
                    info.base_dn = self.base_dn

        except LDAPInvalidCredentialsResult:
            info.error = "Credenziali non valide. Verifica username e password."
        except LDAPSocketOpenError as e:
            info.error = f"Impossibile connettersi al server {self.server_address}:{self.port}. Verifica che il server sia raggiungibile."
        except LDAPBindError as e:
            info.error = f"Errore autenticazione: {str(e)}"
        except LDAPException as e:
            info.error = f"Errore LDAP: {str(e)}"
        except Exception as e:
            info.error = f"Errore connessione: {str(e)}"

        return info

    def disconnect(self):
        """Chiude la connessione"""
        if self._connection:
            self._connection.unbind()
        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Verifica se la connessione è attiva"""
        return self._connected and self._connection and self._connection.bound

    def search(
        self,
        search_filter: str,
        attributes: List[str] = None,
        search_base: str = None,
        scope: str = SUBTREE,
        size_limit: int = 0,
        paged_size: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Esegue ricerca LDAP.

        Args:
            search_filter: Filtro LDAP (es: "(objectClass=user)")
            attributes: Lista attributi da recuperare
            search_base: Base DN per ricerca (default: base_dn)
            scope: Scope ricerca (SUBTREE, BASE, LEVEL)
            size_limit: Limite risultati (0 = nessun limite)
            paged_size: Dimensione pagina per paginazione

        Returns:
            Lista di dizionari con risultati
        """
        if not self.is_connected:
            raise ConnectionError("Non connesso ad Active Directory")

        base = search_base or self.base_dn
        attrs = attributes or ALL_ATTRIBUTES

        results = []

        # Ricerca con paginazione per grandi dataset
        self._connection.search(
            search_base=base,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attrs,
            size_limit=size_limit,
            paged_size=paged_size
        )

        for entry in self._connection.entries:
            result = {
                "dn": entry.entry_dn,
                "attributes": {}
            }
            for attr in entry.entry_attributes:
                value = entry[attr].value
                # Converti valori singoli/multipli
                if isinstance(value, list):
                    result["attributes"][attr] = value
                else:
                    result["attributes"][attr] = value
            results.append(result)

        return results

    def get_domain_policy(self) -> Dict[str, Any]:
        """
        Recupera la Default Domain Policy.

        Returns:
            Dizionario con policy password del dominio
        """
        if not self.is_connected:
            raise ConnectionError("Non connesso ad Active Directory")

        policy = {}

        # Cerca nel dominio root per le policy
        self._connection.search(
            search_base=self.base_dn,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=[
                "minPwdLength",           # Lunghezza minima password
                "pwdHistoryLength",       # Cronologia password
                "maxPwdAge",              # Età massima password
                "minPwdAge",              # Età minima password
                "lockoutThreshold",       # Soglia blocco account
                "lockoutDuration",        # Durata blocco
                "lockOutObservationWindow",  # Finestra osservazione
                "pwdProperties",          # Proprietà (complessità, ecc)
            ]
        )

        if self._connection.entries:
            entry = self._connection.entries[0]

            # Lunghezza minima
            if hasattr(entry, "minPwdLength"):
                policy["min_password_length"] = int(entry.minPwdLength.value or 0)

            # Cronologia
            if hasattr(entry, "pwdHistoryLength"):
                policy["password_history"] = int(entry.pwdHistoryLength.value or 0)

            # Età massima (in intervalli di 100 nanosecondi, negativo)
            if hasattr(entry, "maxPwdAge"):
                max_age = entry.maxPwdAge.value
                if max_age:
                    # Converti in giorni
                    days = abs(int(max_age)) / (10000000 * 60 * 60 * 24)
                    policy["max_password_age_days"] = int(days)
                else:
                    policy["max_password_age_days"] = 0  # Mai scade

            # Età minima
            if hasattr(entry, "minPwdAge"):
                min_age = entry.minPwdAge.value
                if min_age:
                    days = abs(int(min_age)) / (10000000 * 60 * 60 * 24)
                    policy["min_password_age_days"] = int(days)
                else:
                    policy["min_password_age_days"] = 0

            # Soglia blocco
            if hasattr(entry, "lockoutThreshold"):
                policy["lockout_threshold"] = int(entry.lockoutThreshold.value or 0)

            # Durata blocco (in intervalli di 100 nanosecondi, negativo)
            if hasattr(entry, "lockoutDuration"):
                duration = entry.lockoutDuration.value
                if duration:
                    minutes = abs(int(duration)) / (10000000 * 60)
                    policy["lockout_duration_minutes"] = int(minutes)
                else:
                    policy["lockout_duration_minutes"] = 0

            # Proprietà password (bitmask)
            if hasattr(entry, "pwdProperties"):
                props = int(entry.pwdProperties.value or 0)
                # Bit 0: DOMAIN_PASSWORD_COMPLEX
                policy["complexity_enabled"] = bool(props & 1)
                # Bit 1: DOMAIN_PASSWORD_NO_ANON_CHANGE
                policy["no_anon_change"] = bool(props & 2)
                # Bit 2: DOMAIN_PASSWORD_NO_CLEAR_CHANGE
                policy["no_clear_change"] = bool(props & 4)
                # Bit 3: DOMAIN_LOCKOUT_ADMINS
                policy["lockout_admins"] = bool(props & 8)
                # Bit 4: DOMAIN_PASSWORD_STORE_CLEARTEXT
                policy["store_cleartext"] = bool(props & 16)
                # Bit 5: DOMAIN_REFUSE_PASSWORD_CHANGE
                policy["refuse_password_change"] = bool(props & 32)

        return policy

    def get_all_users(
        self,
        include_disabled: bool = True,
        include_computers: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Recupera tutti gli utenti dal dominio.

        Args:
            include_disabled: Includi account disabilitati
            include_computers: Includi account computer

        Returns:
            Lista utenti con attributi rilevanti
        """
        # Filtro base per utenti
        if include_computers:
            search_filter = "(objectClass=user)"
        else:
            search_filter = "(&(objectClass=user)(!(objectClass=computer)))"

        attributes = [
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "distinguishedName",
            "userAccountControl",
            "pwdLastSet",
            "lastLogon",
            "lastLogonTimestamp",
            "whenCreated",
            "whenChanged",
            "memberOf",
            "adminCount",
            "description",
            "accountExpires",
            "msDS-UserPasswordExpiryTimeComputed",
        ]

        return self.search(search_filter, attributes)

    def get_admin_users(self) -> List[Dict[str, Any]]:
        """Recupera utenti con privilegi amministrativi"""
        # Cerca membri di gruppi admin
        admin_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Administrators",
            "Schema Admins",
        ]

        admin_users = []
        seen_dns = set()

        for group in admin_groups:
            filter_str = f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN={group},CN=Users,{self.base_dn}))"
            try:
                users = self.search(
                    filter_str,
                    [
                        "sAMAccountName",
                        "distinguishedName",
                        "userAccountControl",
                        "pwdLastSet",
                        "lastLogon",
                        "memberOf",
                    ]
                )
                for user in users:
                    if user["dn"] not in seen_dns:
                        seen_dns.add(user["dn"])
                        user["admin_group"] = group
                        admin_users.append(user)
            except Exception:
                continue

        return admin_users

    def get_server_info(self) -> Dict[str, Any]:
        """Recupera informazioni sul server AD"""
        if not self._server or not self._server.info:
            return {}

        info = self._server.info
        return {
            "naming_contexts": info.naming_contexts if info.naming_contexts else [],
            "supported_ldap_versions": info.supported_ldap_versions if info.supported_ldap_versions else [],
            "vendor_name": info.vendor_name if info.vendor_name else "Unknown",
            "vendor_version": info.vendor_version if info.vendor_version else "Unknown",
        }


def main():
    """Test connessione AD"""
    print("=" * 60)
    print("ADGuardian - Test Connettore AD")
    print("Sviluppato da ISIPC - Truant Bruno | https://isipc.com")
    print("=" * 60)
    print("\nQuesto modulo richiede un Active Directory per i test.")
    print("Usa: ADConnector('dc.domain.com', 'user@domain.com', 'password')")


if __name__ == "__main__":
    main()
