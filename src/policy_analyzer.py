"""
Policy Analyzer - Analisi delle policy password Active Directory
Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any


class RiskLevel(Enum):
    """Livelli di rischio"""
    CRITICAL = "critical"
    WARNING = "warning"
    OK = "ok"
    INFO = "info"


@dataclass
class PolicyCheck:
    """Risultato verifica singola policy"""
    name: str
    current_value: Any
    recommended_value: Any
    risk_level: RiskLevel
    description: str
    recommendation: str
    compliant: bool


class PolicyAnalyzer:
    """
    Analizza le policy password di Active Directory.
    Confronta con le best practice di sicurezza.
    """

    # Valori raccomandati (basati su NIST, CIS, Microsoft)
    RECOMMENDED = {
        "min_password_length": 12,          # NIST raccomanda 8+, best practice 12+
        "password_history": 12,              # Ricorda ultime 12 password
        "max_password_age_days": 90,         # Cambio ogni 90 giorni (o 365 con MFA)
        "min_password_age_days": 1,          # Almeno 1 giorno prima di cambiare
        "lockout_threshold": 5,              # Blocco dopo 5 tentativi
        "lockout_duration_minutes": 15,      # Blocco 15 minuti
        "complexity_enabled": True,          # Complessità obbligatoria
    }

    # Soglie per classificazione rischio
    THRESHOLDS = {
        "min_password_length": {
            "critical": 6,    # <= 6 è critico
            "warning": 8,     # <= 8 è warning
        },
        "password_history": {
            "critical": 3,    # <= 3 è critico
            "warning": 6,     # <= 6 è warning
        },
        "max_password_age_days": {
            "critical": 0,    # 0 = mai scade, è critico
            "warning": 180,   # > 180 giorni è warning
        },
        "lockout_threshold": {
            "critical": 0,    # 0 = no blocco, è critico
            "warning": 10,    # > 10 tentativi è warning
        },
    }

    def __init__(self):
        """Inizializza l'analizzatore"""
        self.checks: List[PolicyCheck] = []

    def analyze(self, policy: Dict[str, Any]) -> List[PolicyCheck]:
        """
        Analizza la policy password del dominio.

        Args:
            policy: Dizionario con valori policy da ADConnector

        Returns:
            Lista di PolicyCheck con risultati analisi
        """
        self.checks = []

        # 1. Lunghezza minima password
        self._check_min_length(policy.get("min_password_length", 0))

        # 2. Complessità password
        self._check_complexity(policy.get("complexity_enabled", False))

        # 3. Cronologia password
        self._check_history(policy.get("password_history", 0))

        # 4. Età massima password
        self._check_max_age(policy.get("max_password_age_days", 0))

        # 5. Età minima password
        self._check_min_age(policy.get("min_password_age_days", 0))

        # 6. Soglia blocco account
        self._check_lockout_threshold(policy.get("lockout_threshold", 0))

        # 7. Durata blocco
        self._check_lockout_duration(policy.get("lockout_duration_minutes", 0))

        return self.checks

    def _check_min_length(self, value: int):
        """Verifica lunghezza minima password"""
        thresholds = self.THRESHOLDS["min_password_length"]
        recommended = self.RECOMMENDED["min_password_length"]

        if value <= thresholds["critical"]:
            risk = RiskLevel.CRITICAL
            compliant = False
        elif value < thresholds["warning"]:
            risk = RiskLevel.WARNING
            compliant = False
        elif value < recommended:
            risk = RiskLevel.WARNING
            compliant = False
        else:
            risk = RiskLevel.OK
            compliant = True

        self.checks.append(PolicyCheck(
            name="Lunghezza minima password",
            current_value=f"{value} caratteri",
            recommended_value=f"{recommended}+ caratteri",
            risk_level=risk,
            description="Numero minimo di caratteri richiesti per le password.",
            recommendation=self._get_length_recommendation(value, recommended),
            compliant=compliant
        ))

    def _get_length_recommendation(self, current: int, recommended: int) -> str:
        if current <= 6:
            return (
                "URGENTE: Password di 6 caratteri o meno sono facilmente violabili "
                "con attacchi brute-force. Aumentare immediatamente a 12+ caratteri."
            )
        elif current < recommended:
            return (
                f"Aumentare la lunghezza minima da {current} a {recommended} caratteri. "
                "Password più lunghe sono esponenzialmente più sicure."
            )
        return "Configurazione adeguata."

    def _check_complexity(self, enabled: bool):
        """Verifica requisiti complessità"""
        if not enabled:
            risk = RiskLevel.CRITICAL
            compliant = False
            recommendation = (
                "URGENTE: Abilitare i requisiti di complessità password. "
                "Senza complessità, gli utenti possono usare password banali come '123456' o 'password'."
            )
        else:
            risk = RiskLevel.OK
            compliant = True
            recommendation = "Configurazione adeguata."

        self.checks.append(PolicyCheck(
            name="Complessità password",
            current_value="Abilitata" if enabled else "Disabilitata",
            recommended_value="Abilitata",
            risk_level=risk,
            description=(
                "Richiede che le password contengano caratteri di almeno 3 categorie: "
                "maiuscole, minuscole, numeri, simboli."
            ),
            recommendation=recommendation,
            compliant=compliant
        ))

    def _check_history(self, value: int):
        """Verifica cronologia password"""
        thresholds = self.THRESHOLDS["password_history"]
        recommended = self.RECOMMENDED["password_history"]

        if value <= thresholds["critical"]:
            risk = RiskLevel.CRITICAL
            compliant = False
        elif value < thresholds["warning"]:
            risk = RiskLevel.WARNING
            compliant = False
        elif value < recommended:
            risk = RiskLevel.WARNING
            compliant = False
        else:
            risk = RiskLevel.OK
            compliant = True

        self.checks.append(PolicyCheck(
            name="Cronologia password",
            current_value=f"{value} password ricordate",
            recommended_value=f"{recommended} password",
            risk_level=risk,
            description="Numero di password precedenti che non possono essere riutilizzate.",
            recommendation=self._get_history_recommendation(value, recommended),
            compliant=compliant
        ))

    def _get_history_recommendation(self, current: int, recommended: int) -> str:
        if current == 0:
            return (
                "URGENTE: La cronologia password è disabilitata. "
                "Gli utenti possono riutilizzare sempre la stessa password. "
                f"Impostare a {recommended}."
            )
        elif current < recommended:
            return (
                f"Aumentare la cronologia da {current} a {recommended}. "
                "Impedisce agli utenti di alternare tra poche password."
            )
        return "Configurazione adeguata."

    def _check_max_age(self, value: int):
        """Verifica età massima password"""
        recommended = self.RECOMMENDED["max_password_age_days"]

        if value == 0:
            risk = RiskLevel.CRITICAL
            compliant = False
            recommendation = (
                "CRITICO: Le password non scadono mai. "
                "Se una password viene compromessa, rimane valida per sempre. "
                f"Impostare scadenza a {recommended} giorni."
            )
        elif value > 180:
            risk = RiskLevel.WARNING
            compliant = False
            recommendation = (
                f"La scadenza di {value} giorni è troppo lunga. "
                f"Ridurre a {recommended} giorni o meno."
            )
        elif value > recommended:
            risk = RiskLevel.WARNING
            compliant = False
            recommendation = (
                f"Considerare di ridurre da {value} a {recommended} giorni. "
                "Con MFA attivo, fino a 365 giorni può essere accettabile."
            )
        else:
            risk = RiskLevel.OK
            compliant = True
            recommendation = "Configurazione adeguata."

        current_str = f"{value} giorni" if value > 0 else "Mai (infinito)"

        self.checks.append(PolicyCheck(
            name="Scadenza password",
            current_value=current_str,
            recommended_value=f"{recommended} giorni",
            risk_level=risk,
            description="Tempo massimo prima che la password debba essere cambiata.",
            recommendation=recommendation,
            compliant=compliant
        ))

    def _check_min_age(self, value: int):
        """Verifica età minima password"""
        recommended = self.RECOMMENDED["min_password_age_days"]

        if value == 0:
            risk = RiskLevel.WARNING
            compliant = False
            recommendation = (
                "Impostare l'età minima ad almeno 1 giorno. "
                "Senza questo, gli utenti possono cambiare password più volte "
                "in rapida successione per aggirare la cronologia."
            )
        else:
            risk = RiskLevel.OK
            compliant = True
            recommendation = "Configurazione adeguata."

        self.checks.append(PolicyCheck(
            name="Età minima password",
            current_value=f"{value} giorni",
            recommended_value=f"{recommended}+ giorni",
            risk_level=risk,
            description="Tempo minimo che deve passare prima di poter cambiare di nuovo la password.",
            recommendation=recommendation,
            compliant=compliant
        ))

    def _check_lockout_threshold(self, value: int):
        """Verifica soglia blocco account"""
        thresholds = self.THRESHOLDS["lockout_threshold"]
        recommended = self.RECOMMENDED["lockout_threshold"]

        if value == 0:
            risk = RiskLevel.CRITICAL
            compliant = False
            recommendation = (
                "CRITICO: Il blocco account è disabilitato. "
                "Gli attaccanti possono provare infinite password. "
                f"Impostare a {recommended} tentativi."
            )
        elif value > thresholds["warning"]:
            risk = RiskLevel.WARNING
            compliant = False
            recommendation = (
                f"Ridurre la soglia da {value} a {recommended} tentativi. "
                "Un valore troppo alto permette molti tentativi di attacco."
            )
        elif value < 3:
            risk = RiskLevel.WARNING
            compliant = True
            recommendation = (
                f"La soglia di {value} tentativi è molto restrittiva. "
                "Potrebbe causare blocchi frequenti per utenti legittimi."
            )
        else:
            risk = RiskLevel.OK
            compliant = True
            recommendation = "Configurazione adeguata."

        current_str = f"{value} tentativi" if value > 0 else "Disabilitato"

        self.checks.append(PolicyCheck(
            name="Soglia blocco account",
            current_value=current_str,
            recommended_value=f"{recommended} tentativi",
            risk_level=risk,
            description="Numero di tentativi di login falliti prima che l'account venga bloccato.",
            recommendation=recommendation,
            compliant=compliant
        ))

    def _check_lockout_duration(self, value: int):
        """Verifica durata blocco account"""
        recommended = self.RECOMMENDED["lockout_duration_minutes"]

        if value == 0:
            risk = RiskLevel.INFO
            compliant = True
            recommendation = (
                "Il blocco è permanente fino allo sblocco manuale. "
                "Sicuro ma richiede intervento amministratore."
            )
        elif value < 15:
            risk = RiskLevel.WARNING
            compliant = False
            recommendation = (
                f"Aumentare la durata da {value} a {recommended}+ minuti. "
                "Un blocco troppo breve non scoraggia gli attacchi."
            )
        else:
            risk = RiskLevel.OK
            compliant = True
            recommendation = "Configurazione adeguata."

        current_str = f"{value} minuti" if value > 0 else "Permanente (sblocco manuale)"

        self.checks.append(PolicyCheck(
            name="Durata blocco account",
            current_value=current_str,
            recommended_value=f"{recommended}+ minuti",
            risk_level=risk,
            description="Tempo di blocco dell'account dopo troppi tentativi falliti.",
            recommendation=recommendation,
            compliant=compliant
        ))

    def get_summary(self) -> Dict[str, Any]:
        """
        Genera riepilogo dell'analisi.

        Returns:
            Dizionario con statistiche e punteggio
        """
        if not self.checks:
            return {}

        critical = sum(1 for c in self.checks if c.risk_level == RiskLevel.CRITICAL)
        warning = sum(1 for c in self.checks if c.risk_level == RiskLevel.WARNING)
        ok = sum(1 for c in self.checks if c.risk_level == RiskLevel.OK)
        compliant = sum(1 for c in self.checks if c.compliant)

        total = len(self.checks)

        # Calcola punteggio (0-100)
        # Critico: -20 punti, Warning: -10 punti
        base_score = 100
        score = base_score - (critical * 20) - (warning * 10)
        score = max(0, min(100, score))

        # Valutazione complessiva
        if critical > 0:
            assessment = "CRITICO"
            assessment_text = "La policy password presenta problemi gravi che richiedono intervento immediato."
        elif warning > 2:
            assessment = "INSUFFICIENTE"
            assessment_text = "La policy password ha diverse carenze da correggere."
        elif warning > 0:
            assessment = "MIGLIORABILE"
            assessment_text = "La policy password è accettabile ma può essere migliorata."
        else:
            assessment = "ADEGUATA"
            assessment_text = "La policy password è configurata correttamente."

        return {
            "total_checks": total,
            "critical_count": critical,
            "warning_count": warning,
            "ok_count": ok,
            "compliant_count": compliant,
            "compliance_percentage": int((compliant / total) * 100),
            "score": score,
            "assessment": assessment,
            "assessment_text": assessment_text,
        }

    def get_risk_color(self, risk_level: RiskLevel) -> Tuple[int, int, int]:
        """Restituisce colore RGB per livello rischio"""
        colors = {
            RiskLevel.CRITICAL: (220, 53, 69),
            RiskLevel.WARNING: (255, 193, 7),
            RiskLevel.OK: (40, 167, 69),
            RiskLevel.INFO: (23, 162, 184),
        }
        return colors.get(risk_level, (108, 117, 125))


def main():
    """Test analizzatore policy"""
    print("=" * 60)
    print("ADGuardian - Test Policy Analyzer")
    print("Sviluppato da ISIPC - Truant Bruno | https://isipc.com")
    print("=" * 60)

    # Test con policy di esempio (configurazione debole)
    weak_policy = {
        "min_password_length": 6,
        "complexity_enabled": False,
        "password_history": 0,
        "max_password_age_days": 0,
        "min_password_age_days": 0,
        "lockout_threshold": 0,
        "lockout_duration_minutes": 0,
    }

    analyzer = PolicyAnalyzer()
    checks = analyzer.analyze(weak_policy)
    summary = analyzer.get_summary()

    print(f"\nPunteggio: {summary['score']}/100")
    print(f"Valutazione: {summary['assessment']}")
    print(f"\nProblemi critici: {summary['critical_count']}")
    print(f"Attenzione: {summary['warning_count']}")
    print(f"OK: {summary['ok_count']}")

    print("\n" + "-" * 40)
    for check in checks:
        status = "CRITICO" if check.risk_level == RiskLevel.CRITICAL else \
                 "ATTENZIONE" if check.risk_level == RiskLevel.WARNING else "OK"
        print(f"\n{check.name}: {status}")
        print(f"  Attuale: {check.current_value}")
        print(f"  Consigliato: {check.recommended_value}")


if __name__ == "__main__":
    main()
