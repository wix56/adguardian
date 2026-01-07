#!/usr/bin/env python3
"""
ADGuardian - Audit Password Active Directory per PMI italiane
Il guardiano delle password che protegge il tuo dominio

Uso:
    python run.py --server dc.domain.com --username user@domain.com --output report.pdf
    python run.py --server 192.168.1.10 --username DOMAIN\\admin --output report.pdf

Sviluppato da ISIPC - Truant Bruno
https://isipc.com | https://github.com/brunotr88
"""

import argparse
import sys
import os
import getpass
import json
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


def print_banner():
    """Stampa banner applicazione"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗     ║
    ║    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗    ║
    ║    ███████║██║  ██║██║  ███╗██║   ██║███████║██████╔╝    ║
    ║    ██╔══██║██║  ██║██║   ██║██║   ██║██╔══██║██╔══██╗    ║
    ║    ██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║    ║
    ║    ╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ║
    ║                                                           ║
    ║    ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗   ║
    ║   ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗  ║
    ║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║  ║
    ║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║  ║
    ║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║  ║
    ║    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝  ║
    ║                                                           ║
    ║   Il guardiano delle password Active Directory   v1.0.0  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """

    if HAS_COLOR:
        print(Fore.CYAN + banner + Style.RESET_ALL)
    else:
        print(banner)

    print("  Sviluppato da ISIPC - Truant Bruno")
    print("  https://isipc.com | https://github.com/brunotr88")
    print()


def print_colored(text: str, color: str = "white"):
    """Stampa testo colorato"""
    if HAS_COLOR:
        colors_map = {
            "red": Fore.RED,
            "green": Fore.GREEN,
            "yellow": Fore.YELLOW,
            "blue": Fore.BLUE,
            "cyan": Fore.CYAN,
            "white": Fore.WHITE,
        }
        print(colors_map.get(color, Fore.WHITE) + text + Style.RESET_ALL)
    else:
        print(text)


def main():
    """Funzione principale"""
    parser = argparse.ArgumentParser(
        description="ADGuardian - Audit Password Active Directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  %(prog)s --server dc.example.com --username admin@example.com
  %(prog)s --server 192.168.1.10 --username DOMAIN\\admin --no-ssl
  %(prog)s --server dc.local --username user@domain.local --output audit.pdf

Password:
  La password può essere fornita tramite:
  - Prompt interattivo (consigliato)
  - Variabile ambiente ADGUARDIAN_PASSWORD
  - Opzione --password (sconsigliato, visibile in history)

Sviluppato da ISIPC - Truant Bruno | https://isipc.com
        """
    )

    parser.add_argument(
        "-s", "--server",
        required=True,
        help="Hostname o IP del Domain Controller"
    )

    parser.add_argument(
        "-u", "--username",
        required=True,
        help="Username (user@domain.com o DOMAIN\\user)"
    )

    parser.add_argument(
        "-p", "--password",
        help="Password (meglio usare prompt interattivo)"
    )

    parser.add_argument(
        "-d", "--domain",
        help="Nome dominio (se non specificato, estratto da username)"
    )

    parser.add_argument(
        "-o", "--output",
        default="adguardian_report.pdf",
        help="File PDF di output (default: adguardian_report.pdf)"
    )

    parser.add_argument(
        "--json",
        help="Salva anche risultati in formato JSON"
    )

    parser.add_argument(
        "--no-ssl",
        action="store_true",
        help="Usa LDAP (389) invece di LDAPS (636)"
    )

    parser.add_argument(
        "--skip-cert-check",
        action="store_true",
        help="Non verificare certificato SSL (non consigliato)"
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Porta personalizzata"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout connessione in secondi (default: 30)"
    )

    parser.add_argument(
        "--inactive-days",
        type=int,
        default=90,
        help="Giorni senza login per considerare account inattivo (default: 90)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Output dettagliato"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="ADGuardian v1.0.0 - ISIPC - Truant Bruno"
    )

    args = parser.parse_args()

    # Mostra banner
    print_banner()

    # Ottieni password
    password = args.password
    if not password:
        password = os.environ.get("ADGUARDIAN_PASSWORD")
    if not password:
        try:
            password = getpass.getpass(
                f"Password per {args.username}: "
            )
        except KeyboardInterrupt:
            print("\n")
            print_colored("[!] Operazione annullata", "yellow")
            sys.exit(130)

    if not password:
        print_colored("[!] Password richiesta", "red")
        sys.exit(1)

    # Importa moduli (qui per velocizzare --help)
    try:
        from src.ad_connector import ADConnector
        from src.policy_analyzer import PolicyAnalyzer
        from src.user_auditor import UserAuditor
        from src.report_generator import ReportGenerator
    except ImportError as e:
        print_colored(f"[!] Errore import: {e}", "red")
        print_colored("[*] Installa dipendenze: pip install -r requirements.txt", "yellow")
        sys.exit(1)

    # Connessione AD
    print_colored(f"[*] Connessione a {args.server}...", "cyan")

    connector = ADConnector(
        server=args.server,
        username=args.username,
        password=password,
        domain=args.domain,
        use_ssl=not args.no_ssl,
        port=args.port,
        timeout=args.timeout,
        validate_cert=not args.skip_cert_check
    )

    conn_info = connector.connect()

    if not conn_info.connected:
        print_colored(f"[!] Connessione fallita: {conn_info.error}", "red")
        sys.exit(1)

    print_colored(f"[+] Connesso a {conn_info.domain}", "green")
    print_colored(f"[*] Base DN: {conn_info.base_dn}", "cyan")
    print()

    # Fase 1: Analisi Policy
    print_colored("[*] Analisi policy password dominio...", "cyan")

    try:
        domain_policy = connector.get_domain_policy()
    except Exception as e:
        print_colored(f"[!] Errore lettura policy: {e}", "red")
        domain_policy = {}

    policy_analyzer = PolicyAnalyzer()
    policy_checks = policy_analyzer.analyze(domain_policy)
    policy_summary = policy_analyzer.get_summary()

    print_colored(f"[+] Policy analizzata - Punteggio: {policy_summary['score']}/100", "green")

    if policy_summary['critical_count'] > 0:
        print_colored(
            f"    [!] {policy_summary['critical_count']} problemi critici trovati",
            "red"
        )

    # Fase 2: Audit Utenti
    print()
    print_colored("[*] Recupero account utente...", "cyan")

    try:
        users = connector.get_all_users()
        print_colored(f"[+] {len(users)} account trovati", "green")
    except Exception as e:
        print_colored(f"[!] Errore lettura utenti: {e}", "red")
        users = []

    admin_users = []
    try:
        admin_users = connector.get_admin_users()
        if admin_users:
            print_colored(f"[*] {len(admin_users)} account admin identificati", "cyan")
    except Exception as e:
        if args.verbose:
            print_colored(f"[*] Info admin non disponibile: {e}", "yellow")

    print_colored("[*] Analisi account utente...", "cyan")

    user_auditor = UserAuditor(inactive_days=args.inactive_days)
    user_issues = user_auditor.audit_users(users, admin_users)
    user_summary = user_auditor.get_summary()

    print_colored(f"[+] Audit completato - Punteggio: {user_summary['score']}/100", "green")

    if user_summary['critical_count'] > 0:
        print_colored(
            f"    [!] {user_summary['critical_count']} account con problemi critici",
            "red"
        )
    if user_summary['warning_count'] > 0:
        print_colored(
            f"    [!] {user_summary['warning_count']} account da verificare",
            "yellow"
        )

    # Chiudi connessione
    connector.disconnect()

    # Fase 3: Genera Report
    print()
    print_colored(f"[*] Generazione report PDF: {args.output}", "cyan")

    try:
        generator = ReportGenerator()
        output_path = generator.generate(
            domain=conn_info.domain,
            policy_checks=policy_checks,
            policy_summary=policy_summary,
            user_issues=user_issues,
            user_summary=user_summary,
            output_path=args.output
        )
        print_colored(f"[+] Report generato: {output_path}", "green")
    except Exception as e:
        print_colored(f"[!] Errore generazione PDF: {e}", "red")
        print_colored("[*] Installa reportlab: pip install reportlab", "yellow")

    # Salva JSON se richiesto
    if args.json:
        json_data = {
            "domain": conn_info.domain,
            "scan_date": datetime.now().isoformat(),
            "policy": {
                "checks": [
                    {
                        "name": c.name,
                        "current_value": str(c.current_value),
                        "recommended_value": str(c.recommended_value),
                        "risk_level": c.risk_level.value,
                        "compliant": c.compliant,
                    }
                    for c in policy_checks
                ],
                "summary": policy_summary
            },
            "users": {
                "issues": [
                    {
                        "username": i.username,
                        "issue_type": i.issue_type,
                        "risk_level": i.risk_level.value,
                        "description": i.description,
                    }
                    for i in user_issues
                ],
                "summary": user_summary
            }
        }

        try:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            print_colored(f"[+] JSON salvato: {args.json}", "green")
        except Exception as e:
            print_colored(f"[!] Errore salvataggio JSON: {e}", "red")

    # Riepilogo finale
    print()
    print_colored("=" * 60, "cyan")
    print_colored("RIEPILOGO AUDIT", "cyan")
    print_colored("=" * 60, "cyan")

    combined_score = int((policy_summary['score'] + user_summary['score']) / 2)

    print()
    print(f"  Dominio: {conn_info.domain}")
    print(f"  Account analizzati: {user_summary['total_users']}")
    print()
    print(f"  Punteggio Policy: {policy_summary['score']}/100")
    print(f"  Punteggio Account: {user_summary['score']}/100")
    print(f"  Punteggio Complessivo: {combined_score}/100")
    print()

    if policy_summary['critical_count'] > 0 or user_summary['critical_count'] > 0:
        print_colored(
            "  [!] ATTENZIONE: Trovati problemi critici!",
            "red"
        )
        print_colored(
            "      Consulta il report PDF per le raccomandazioni.",
            "yellow"
        )
    elif combined_score < 60:
        print_colored(
            "  [*] La configurazione richiede miglioramenti.",
            "yellow"
        )
    else:
        print_colored(
            "  [+] Configurazione generalmente adeguata.",
            "green"
        )

    print()
    print("  Grazie per aver usato ADGuardian!")
    print("  ISIPC - Truant Bruno | https://isipc.com")
    print()


if __name__ == "__main__":
    main()
