"""
Report Generator - Generazione PDF per ADGuardian
Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

from datetime import datetime
from typing import Dict, List, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)

from .policy_analyzer import PolicyCheck, RiskLevel as PolicyRisk
from .user_auditor import UserIssue, UserRisk


class ReportGenerator:
    """
    Genera report PDF professionale per audit AD.
    Report ottimizzato per non-tecnici con spiegazioni chiare.
    """

    COLORS = {
        'primary': colors.HexColor('#1a365d'),
        'secondary': colors.HexColor('#38a169'),
        'critical': colors.HexColor('#dc3545'),
        'warning': colors.HexColor('#ffc107'),
        'ok': colors.HexColor('#28a745'),
        'info': colors.HexColor('#17a2b8'),
        'light_gray': colors.HexColor('#f8f9fa'),
        'dark_gray': colors.HexColor('#343a40'),
        'text': colors.HexColor('#212529'),
    }

    def __init__(self):
        """Inizializza il generatore"""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Configura stili personalizzati"""
        self.styles.add(ParagraphStyle(
            name='MainTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            textColor=self.COLORS['primary'],
            alignment=TA_CENTER,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='SubTitle',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=self.COLORS['dark_gray'],
            alignment=TA_CENTER,
            spaceAfter=30
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=self.COLORS['primary'],
            spaceBefore=20,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['text'],
            alignment=TA_JUSTIFY,
            spaceAfter=8,
            leading=14
        ))

        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['critical'],
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=self.COLORS['dark_gray'],
            alignment=TA_CENTER
        ))

    def _create_header(self, domain: str, scan_date: datetime) -> List:
        """Crea header del report"""
        elements = []

        elements.append(Paragraph("ADGUARDIAN", self.styles['MainTitle']))
        elements.append(Paragraph(
            "Audit Sicurezza Password Active Directory",
            self.styles['SubTitle']
        ))

        info_data = [
            ["Dominio analizzato:", domain],
            ["Data audit:", scan_date.strftime("%d/%m/%Y alle %H:%M")],
            ["Generato da:", "ADGuardian v1.0.0"]
        ]

        info_table = Table(info_data, colWidths=[5*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLORS['text']),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(info_table)
        elements.append(Spacer(1, 20))

        return elements

    def _create_executive_summary(
        self,
        policy_summary: Dict,
        user_summary: Dict
    ) -> List:
        """Crea riepilogo esecutivo"""
        elements = []

        elements.append(Paragraph("Riepilogo Esecutivo", self.styles['SectionHeader']))

        # Calcola punteggio combinato
        combined_score = int((policy_summary['score'] + user_summary['score']) / 2)

        # Determina colore e testo
        if policy_summary['critical_count'] > 0 or user_summary['critical_count'] > 3:
            risk_color = self.COLORS['critical']
            risk_text = "RISCHIO ALTO"
            risk_desc = "Sono stati rilevati problemi critici che richiedono intervento immediato."
        elif combined_score < 60:
            risk_color = self.COLORS['warning']
            risk_text = "RISCHIO MEDIO"
            risk_desc = "La configurazione presenta carenze da correggere."
        else:
            risk_color = self.COLORS['ok']
            risk_text = "RISCHIO BASSO"
            risk_desc = "La configurazione è generalmente adeguata."

        # Box riepilogo
        summary_data = [
            [Paragraph(
                f"<font size='20'><b>{risk_text}</b></font>",
                ParagraphStyle('risk', alignment=TA_CENTER, textColor=risk_color)
            )],
            [Paragraph(
                f"Punteggio complessivo: <b>{combined_score}/100</b>",
                ParagraphStyle('score', alignment=TA_CENTER, fontSize=12)
            )],
            [Paragraph(risk_desc, ParagraphStyle('desc', alignment=TA_CENTER, fontSize=10))]
        ]

        summary_table = Table(summary_data, colWidths=[15*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['light_gray']),
            ('BOX', (0, 0), (-1, -1), 2, risk_color),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Statistiche
        stats_data = [
            ["Policy Password", "Account Utente"],
            [
                f"Punteggio: {policy_summary['score']}/100",
                f"Punteggio: {user_summary['score']}/100"
            ],
            [
                f"Problemi critici: {policy_summary['critical_count']}",
                f"Problemi critici: {user_summary['critical_count']}"
            ],
            [
                f"Attenzione: {policy_summary['warning_count']}",
                f"Attenzione: {user_summary['warning_count']}"
            ],
        ]

        stats_table = Table(stats_data, colWidths=[7.5*cm, 7.5*cm])
        stats_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, self.COLORS['light_gray']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(stats_table)
        elements.append(Spacer(1, 20))

        # Spiegazione per non-tecnici
        elements.append(Paragraph(
            "<b>Cosa significa questo report?</b>",
            self.styles['BodyText']
        ))
        elements.append(Paragraph(
            "Abbiamo analizzato la configurazione delle password nel vostro dominio "
            "Active Directory. Le password sono la prima linea di difesa contro gli "
            "attacchi informatici. Questo report verifica se le regole per le password "
            "sono adeguate e se ci sono account utente con configurazioni pericolose.",
            self.styles['BodyText']
        ))

        return elements

    def _create_policy_section(self, checks: List[PolicyCheck]) -> List:
        """Crea sezione analisi policy"""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph(
            "Analisi Policy Password Dominio",
            self.styles['SectionHeader']
        ))

        elements.append(Paragraph(
            "La policy password del dominio definisce le regole che tutti gli utenti "
            "devono seguire quando creano o cambiano la password.",
            self.styles['BodyText']
        ))
        elements.append(Spacer(1, 10))

        # Tabella policy
        data = [["Impostazione", "Valore Attuale", "Raccomandato", "Stato"]]

        for check in checks:
            if check.risk_level == PolicyRisk.CRITICAL:
                status = "CRITICO"
                status_color = self.COLORS['critical']
            elif check.risk_level == PolicyRisk.WARNING:
                status = "ATTENZIONE"
                status_color = self.COLORS['warning']
            else:
                status = "OK"
                status_color = self.COLORS['ok']

            data.append([
                check.name,
                str(check.current_value),
                str(check.recommended_value),
                Paragraph(f"<font color='{status_color.hexval()}'><b>{status}</b></font>",
                         ParagraphStyle('status', fontSize=9))
            ])

        policy_table = Table(data, colWidths=[4.5*cm, 3.5*cm, 3.5*cm, 3.5*cm])
        policy_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['light_gray']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_gray']]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(policy_table)
        elements.append(Spacer(1, 20))

        # Dettaglio problemi critici
        critical_checks = [c for c in checks if c.risk_level == PolicyRisk.CRITICAL]
        if critical_checks:
            elements.append(Paragraph(
                "<font color='#dc3545'><b>Problemi Critici nella Policy</b></font>",
                self.styles['BodyText']
            ))

            for check in critical_checks:
                elements.append(Paragraph(
                    f"<b>{check.name}</b>: {check.recommendation}",
                    self.styles['BodyText']
                ))

        return elements

    def _create_users_section(
        self,
        issues: List[UserIssue],
        summary: Dict
    ) -> List:
        """Crea sezione problemi utenti"""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph(
            "Analisi Account Utente",
            self.styles['SectionHeader']
        ))

        # Statistiche utenti
        stats_text = (
            f"Account totali: {summary['total_users']} | "
            f"Attivi: {summary['active_users']} | "
            f"Disabilitati: {summary['disabled_users']}"
        )
        elements.append(Paragraph(stats_text, self.styles['BodyText']))
        elements.append(Spacer(1, 10))

        # Problemi critici
        critical = [i for i in issues if i.risk_level == UserRisk.CRITICAL]
        if critical:
            elements.append(Paragraph(
                "<font color='#dc3545'><b>Account con Problemi Critici</b></font>",
                self.styles['BodyText']
            ))

            crit_data = [["Account", "Problema", "Azione Richiesta"]]
            for issue in critical[:20]:  # Max 20 per evitare report troppo lunghi
                crit_data.append([
                    issue.username,
                    issue.description,
                    issue.recommendation[:100] + "..." if len(issue.recommendation) > 100 else issue.recommendation
                ])

            crit_table = Table(crit_data, colWidths=[3.5*cm, 5*cm, 6.5*cm])
            crit_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['critical']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['light_gray']),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(crit_table)
            elements.append(Spacer(1, 15))

        # Problemi warning
        warnings = [i for i in issues if i.risk_level == UserRisk.WARNING]
        if warnings:
            elements.append(Paragraph(
                "<font color='#856404'><b>Account da Verificare</b></font>",
                self.styles['BodyText']
            ))

            warn_data = [["Account", "Problema"]]
            for issue in warnings[:30]:
                warn_data.append([issue.username, issue.description])

            warn_table = Table(warn_data, colWidths=[5*cm, 10*cm])
            warn_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['warning']),
                ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['dark_gray']),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['light_gray']),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_gray']]),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(warn_table)

        return elements

    def _create_recommendations(
        self,
        policy_summary: Dict,
        user_summary: Dict
    ) -> List:
        """Crea sezione raccomandazioni"""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph(
            "Raccomandazioni e Prossimi Passi",
            self.styles['SectionHeader']
        ))

        priorities = []

        # Priorità 1 - Urgenti
        if policy_summary['critical_count'] > 0 or user_summary['critical_count'] > 0:
            priorities.append(
                "<b>PRIORITÀ 1 - URGENTE:</b><br/>"
                "- Correggere immediatamente le configurazioni critiche della policy<br/>"
                "- Rimuovere il flag 'Password never expires' dagli account admin<br/>"
                "- Eliminare account con flag 'Password not required'"
            )

        # Priorità 2 - Importanti
        if policy_summary['warning_count'] > 0 or user_summary['warning_count'] > 0:
            priorities.append(
                "<b>PRIORITÀ 2 - IMPORTANTE:</b><br/>"
                "- Rivedere la policy password secondo le best practice<br/>"
                "- Verificare e disabilitare account inattivi<br/>"
                "- Implementare il cambio password per account con password vecchie"
            )

        # Best practice generali
        priorities.append(
            "<b>PRIORITÀ 3 - BEST PRACTICE:</b><br/>"
            "- Implementare Multi-Factor Authentication (MFA)<br/>"
            "- Considerare l'uso di Fine-Grained Password Policies<br/>"
            "- Pianificare audit periodici (mensili/trimestrali)<br/>"
            "- Formare gli utenti sulla sicurezza delle password"
        )

        for priority in priorities:
            elements.append(Paragraph(priority, self.styles['BodyText']))
            elements.append(Spacer(1, 10))

        return elements

    def _create_footer(self) -> List:
        """Crea footer del report"""
        elements = []

        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(
            width="100%", thickness=1,
            color=self.COLORS['primary'], spaceAfter=10
        ))

        elements.append(Paragraph(
            "Report generato da <b>ADGuardian</b> - Il guardiano delle password Active Directory",
            self.styles['Footer']
        ))
        elements.append(Paragraph(
            "Sviluppato da <b>ISIPC - Truant Bruno</b> | "
            "<link href='https://isipc.com'>isipc.com</link> | "
            "<link href='https://github.com/brunotr88'>github.com/brunotr88</link>",
            self.styles['Footer']
        ))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            "<i>Nota: Questo report fornisce una valutazione di base. "
            "Non sostituisce un audit di sicurezza professionale completo.</i>",
            ParagraphStyle('disclaimer', fontSize=7, textColor=self.COLORS['dark_gray'],
                          alignment=TA_CENTER)
        ))

        return elements

    def generate(
        self,
        domain: str,
        policy_checks: List[PolicyCheck],
        policy_summary: Dict,
        user_issues: List[UserIssue],
        user_summary: Dict,
        output_path: str
    ) -> str:
        """
        Genera il report PDF completo.

        Args:
            domain: Nome dominio AD
            policy_checks: Risultati analisi policy
            policy_summary: Riepilogo policy
            user_issues: Problemi utenti
            user_summary: Riepilogo utenti
            output_path: Percorso file PDF

        Returns:
            Percorso del file generato
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        elements = []

        # Header
        elements.extend(self._create_header(domain, datetime.now()))

        # Executive Summary
        elements.extend(self._create_executive_summary(policy_summary, user_summary))

        # Policy Analysis
        elements.extend(self._create_policy_section(policy_checks))

        # User Analysis
        elements.extend(self._create_users_section(user_issues, user_summary))

        # Recommendations
        elements.extend(self._create_recommendations(policy_summary, user_summary))

        # Footer
        elements.extend(self._create_footer())

        # Build PDF
        doc.build(elements)

        return output_path


def main():
    """Test generatore report"""
    print("=" * 60)
    print("ADGuardian - Test Report Generator")
    print("Sviluppato da ISIPC - Truant Bruno | https://isipc.com")
    print("=" * 60)
    print("\nQuesto modulo genera report PDF per audit AD.")


if __name__ == "__main__":
    main()
