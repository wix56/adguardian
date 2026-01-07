"""
User Auditor - Audit degli account utente Active Directory
Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class UserRisk(Enum):
    """Livelli di rischio per utenti"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


@dataclass
class UserIssue:
    """Problema rilevato su un account utente"""
    username: str
    display_name: str
    dn: str
    issue_type: str
    risk_level: UserRisk
    description: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)


# Costanti per userAccountControl flags
UAC_FLAGS = {
    "ACCOUNTDISABLE": 0x0002,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
    "NORMAL_ACCOUNT": 0x0200,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "PASSWORD_EXPIRED": 0x800000,
}

# Windows FILETIME epoch (1601-01-01)
FILETIME_EPOCH = datetime(1601, 1, 1)


class UserAuditor:
    """
    Analizza gli account utente Active Directory per problemi di sicurezza.
    """

    # Soglie configurabili
    INACTIVE_DAYS = 90          # Giorni senza login per considerare inattivo
    OLD_PASSWORD_DAYS = 180     # Password più vecchia di X giorni
    NEVER_LOGGED_DAYS = 30      # Account creato da X giorni ma mai loggato

    def __init__(
        self,
        inactive_days: int = 90,
        old_password_days: int = 180
    ):
        """
        Inizializza l'auditor.

        Args:
            inactive_days: Giorni senza login per considerare inattivo
            old_password_days: Età password per considerarla vecchia
        """
        self.inactive_days = inactive_days
        self.old_password_days = old_password_days
        self.issues: List[UserIssue] = []
        self.stats = {
            "total_users": 0,
            "active_users": 0,
            "disabled_users": 0,
            "admin_users": 0,
            "password_never_expires": 0,
            "password_not_required": 0,
            "inactive_users": 0,
            "never_logged_in": 0,
            "old_password": 0,
        }

    def _filetime_to_datetime(self, filetime: int) -> Optional[datetime]:
        """Converte Windows FILETIME in datetime"""
        if not filetime or filetime == 0:
            return None
        try:
            # FILETIME è in 100-nanosecondi dal 1601-01-01
            delta = timedelta(microseconds=filetime // 10)
            return FILETIME_EPOCH + delta
        except (ValueError, OverflowError):
            return None

    def _parse_uac(self, uac_value: int) -> Dict[str, bool]:
        """Parsa userAccountControl flags"""
        return {
            name: bool(uac_value & flag)
            for name, flag in UAC_FLAGS.items()
        }

    def _get_username(self, user: Dict) -> str:
        """Estrae username dall'entry utente"""
        attrs = user.get("attributes", {})
        return attrs.get("sAMAccountName", "Unknown")

    def _get_display_name(self, user: Dict) -> str:
        """Estrae display name dall'entry utente"""
        attrs = user.get("attributes", {})
        return attrs.get("displayName") or attrs.get("sAMAccountName", "Unknown")

    def audit_users(
        self,
        users: List[Dict[str, Any]],
        admin_users: Optional[List[Dict[str, Any]]] = None
    ) -> List[UserIssue]:
        """
        Esegue audit completo degli utenti.

        Args:
            users: Lista utenti da ADConnector.get_all_users()
            admin_users: Lista utenti admin (opzionale)

        Returns:
            Lista di UserIssue con problemi rilevati
        """
        self.issues = []
        now = datetime.now()
        admin_dns = set()

        if admin_users:
            admin_dns = {u.get("dn", "") for u in admin_users}
            self.stats["admin_users"] = len(admin_dns)

        self.stats["total_users"] = len(users)

        for user in users:
            attrs = user.get("attributes", {})
            dn = user.get("dn", "")
            username = self._get_username(user)
            display_name = self._get_display_name(user)

            # Parse userAccountControl
            uac = int(attrs.get("userAccountControl", 0) or 0)
            uac_flags = self._parse_uac(uac)

            # Account disabilitato
            is_disabled = uac_flags.get("ACCOUNTDISABLE", False)
            if is_disabled:
                self.stats["disabled_users"] += 1
                continue  # Skip disabled accounts per le altre analisi
            else:
                self.stats["active_users"] += 1

            # È admin?
            is_admin = dn in admin_dns

            # 1. Password Never Expires
            if uac_flags.get("DONT_EXPIRE_PASSWORD", False):
                self.stats["password_never_expires"] += 1
                risk = UserRisk.CRITICAL if is_admin else UserRisk.WARNING

                self.issues.append(UserIssue(
                    username=username,
                    display_name=display_name,
                    dn=dn,
                    issue_type="PASSWORD_NEVER_EXPIRES",
                    risk_level=risk,
                    description="La password di questo account non scade mai.",
                    recommendation=(
                        "URGENTE: " if is_admin else ""
                    ) + "Rimuovere il flag 'Password never expires'. "
                    "Se una password viene compromessa, rimane valida per sempre.",
                    details={"is_admin": is_admin}
                ))

            # 2. Password Not Required
            if uac_flags.get("PASSWD_NOTREQD", False):
                self.stats["password_not_required"] += 1

                self.issues.append(UserIssue(
                    username=username,
                    display_name=display_name,
                    dn=dn,
                    issue_type="PASSWORD_NOT_REQUIRED",
                    risk_level=UserRisk.CRITICAL,
                    description="Questo account può avere una password vuota.",
                    recommendation=(
                        "URGENTE: Rimuovere il flag 'Password not required'. "
                        "Un account senza password è completamente esposto."
                    ),
                    details={"is_admin": is_admin}
                ))

            # 3. Last Logon - Account inattivo
            last_logon = attrs.get("lastLogonTimestamp") or attrs.get("lastLogon")
            if last_logon:
                last_logon_dt = self._filetime_to_datetime(int(last_logon))
                if last_logon_dt:
                    days_inactive = (now - last_logon_dt).days
                    if days_inactive > self.inactive_days:
                        self.stats["inactive_users"] += 1

                        self.issues.append(UserIssue(
                            username=username,
                            display_name=display_name,
                            dn=dn,
                            issue_type="INACTIVE_ACCOUNT",
                            risk_level=UserRisk.WARNING,
                            description=f"Account non utilizzato da {days_inactive} giorni.",
                            recommendation=(
                                f"Verificare se l'account è ancora necessario. "
                                f"Account inattivi sono un rischio se compromessi."
                            ),
                            details={
                                "last_logon": last_logon_dt.isoformat(),
                                "days_inactive": days_inactive
                            }
                        ))
            else:
                # Mai loggato
                when_created = attrs.get("whenCreated")
                if when_created:
                    # whenCreated è già in formato datetime string
                    try:
                        if isinstance(when_created, datetime):
                            created_dt = when_created
                        else:
                            created_dt = datetime.strptime(
                                str(when_created)[:14], "%Y%m%d%H%M%S"
                            )
                        days_since_created = (now - created_dt).days
                        if days_since_created > self.NEVER_LOGGED_DAYS:
                            self.stats["never_logged_in"] += 1

                            self.issues.append(UserIssue(
                                username=username,
                                display_name=display_name,
                                dn=dn,
                                issue_type="NEVER_LOGGED_IN",
                                risk_level=UserRisk.INFO,
                                description=(
                                    f"Account creato {days_since_created} giorni fa "
                                    "ma mai utilizzato."
                                ),
                                recommendation=(
                                    "Verificare se l'account è ancora necessario. "
                                    "Account mai usati potrebbero essere stati creati "
                                    "per errore o non più necessari."
                                ),
                                details={
                                    "created": created_dt.isoformat(),
                                    "days_since_created": days_since_created
                                }
                            ))
                    except (ValueError, TypeError):
                        pass

            # 4. Password vecchia
            pwd_last_set = attrs.get("pwdLastSet")
            if pwd_last_set and int(pwd_last_set) > 0:
                pwd_dt = self._filetime_to_datetime(int(pwd_last_set))
                if pwd_dt:
                    pwd_age_days = (now - pwd_dt).days
                    if pwd_age_days > self.old_password_days:
                        self.stats["old_password"] += 1
                        risk = UserRisk.WARNING if is_admin else UserRisk.INFO

                        self.issues.append(UserIssue(
                            username=username,
                            display_name=display_name,
                            dn=dn,
                            issue_type="OLD_PASSWORD",
                            risk_level=risk,
                            description=f"Password non cambiata da {pwd_age_days} giorni.",
                            recommendation=(
                                "Richiedere cambio password. Password molto vecchie "
                                "hanno maggior probabilità di essere state compromesse."
                            ),
                            details={
                                "password_age_days": pwd_age_days,
                                "last_change": pwd_dt.isoformat(),
                                "is_admin": is_admin
                            }
                        ))

        return self.issues

    def get_issues_by_risk(self, risk_level: UserRisk) -> List[UserIssue]:
        """Filtra issues per livello di rischio"""
        return [i for i in self.issues if i.risk_level == risk_level]

    def get_issues_by_type(self, issue_type: str) -> List[UserIssue]:
        """Filtra issues per tipo"""
        return [i for i in self.issues if i.issue_type == issue_type]

    def get_summary(self) -> Dict[str, Any]:
        """
        Genera riepilogo dell'audit utenti.

        Returns:
            Dizionario con statistiche e valutazione
        """
        critical = len(self.get_issues_by_risk(UserRisk.CRITICAL))
        warning = len(self.get_issues_by_risk(UserRisk.WARNING))
        info = len(self.get_issues_by_risk(UserRisk.INFO))

        # Calcola punteggio
        # Critico: -15 punti, Warning: -5 punti, Info: -1 punto
        base_score = 100
        score = base_score - (critical * 15) - (warning * 5) - (info * 1)
        score = max(0, min(100, score))

        # Valutazione
        if critical > 5:
            assessment = "CRITICO"
            assessment_text = "Numerosi account presentano problemi gravi di sicurezza."
        elif critical > 0:
            assessment = "ATTENZIONE"
            assessment_text = "Alcuni account hanno configurazioni pericolose."
        elif warning > 10:
            assessment = "MIGLIORABILE"
            assessment_text = "Diversi account richiedono attenzione."
        elif warning > 0:
            assessment = "BUONO"
            assessment_text = "Pochi problemi rilevati, situazione sotto controllo."
        else:
            assessment = "OTTIMO"
            assessment_text = "Gli account utente sono ben configurati."

        return {
            "total_users": self.stats["total_users"],
            "active_users": self.stats["active_users"],
            "disabled_users": self.stats["disabled_users"],
            "admin_users": self.stats["admin_users"],
            "total_issues": len(self.issues),
            "critical_count": critical,
            "warning_count": warning,
            "info_count": info,
            "password_never_expires": self.stats["password_never_expires"],
            "password_not_required": self.stats["password_not_required"],
            "inactive_users": self.stats["inactive_users"],
            "never_logged_in": self.stats["never_logged_in"],
            "old_password": self.stats["old_password"],
            "score": score,
            "assessment": assessment,
            "assessment_text": assessment_text,
        }


def main():
    """Test auditor utenti"""
    print("=" * 60)
    print("ADGuardian - Test User Auditor")
    print("Sviluppato da ISIPC - Truant Bruno | https://isipc.com")
    print("=" * 60)

    # Simula dati utente per test
    now = datetime.now()
    old_filetime = int((now - timedelta(days=200) - FILETIME_EPOCH).total_seconds() * 10000000)
    recent_filetime = int((now - timedelta(days=5) - FILETIME_EPOCH).total_seconds() * 10000000)

    test_users = [
        {
            "dn": "CN=Admin Test,OU=Users,DC=test,DC=local",
            "attributes": {
                "sAMAccountName": "admin.test",
                "displayName": "Admin Test",
                "userAccountControl": 66048,  # NORMAL + DONT_EXPIRE_PASSWORD
                "pwdLastSet": old_filetime,
                "lastLogonTimestamp": recent_filetime,
            }
        },
        {
            "dn": "CN=User NoPassword,OU=Users,DC=test,DC=local",
            "attributes": {
                "sAMAccountName": "user.nopassword",
                "displayName": "User NoPassword",
                "userAccountControl": 544,  # NORMAL + PASSWD_NOTREQD
                "pwdLastSet": recent_filetime,
                "lastLogonTimestamp": recent_filetime,
            }
        },
        {
            "dn": "CN=User OK,OU=Users,DC=test,DC=local",
            "attributes": {
                "sAMAccountName": "user.ok",
                "displayName": "User OK",
                "userAccountControl": 512,  # NORMAL only
                "pwdLastSet": recent_filetime,
                "lastLogonTimestamp": recent_filetime,
            }
        },
    ]

    auditor = UserAuditor()
    issues = auditor.audit_users(test_users)
    summary = auditor.get_summary()

    print(f"\nUtenti analizzati: {summary['total_users']}")
    print(f"Problemi trovati: {summary['total_issues']}")
    print(f"  - Critici: {summary['critical_count']}")
    print(f"  - Attenzione: {summary['warning_count']}")
    print(f"  - Info: {summary['info_count']}")
    print(f"\nPunteggio: {summary['score']}/100")
    print(f"Valutazione: {summary['assessment']}")

    if issues:
        print("\n" + "-" * 40)
        print("Problemi rilevati:")
        for issue in issues:
            print(f"\n  [{issue.risk_level.value.upper()}] {issue.username}")
            print(f"  Tipo: {issue.issue_type}")
            print(f"  {issue.description}")


if __name__ == "__main__":
    main()
