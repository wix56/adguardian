# ADGuardian

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Made in Italy](https://img.shields.io/badge/Made%20in-Italy%20🇮🇹-red.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)

**Il guardiano delle password che protegge il tuo dominio Active Directory**

Audit completo delle policy password e degli account utente Active Directory. Genera report PDF chiari e comprensibili per PMI italiane.

---

## 🎯 A cosa serve?

ADGuardian analizza la configurazione delle password nel tuo dominio Active Directory per trovare:

- ✅ **Policy password deboli** (lunghezza minima, complessità, scadenza)
- ✅ **Account con "Password never expires"** (rischio se compromessi)
- ✅ **Account senza password obbligatoria** (flag PASSWD_NOTREQD)
- ✅ **Account inattivi** (non usati da 90+ giorni)
- ✅ **Account admin con configurazioni pericolose**

Il report PDF spiega ogni problema in italiano semplice con raccomandazioni concrete.

---

## 🚀 Installazione

### Requisiti
- Python 3.8 o superiore
- Accesso LDAP al Domain Controller
- Credenziali utente con permessi di lettura AD

### Installazione

```bash
git clone https://github.com/brunotr88/adguardian.git
cd adguardian
pip install -r requirements.txt
```

---

## 📖 Uso

### Audit completo con output PDF

```bash
python run.py --server dc.example.com --username admin@example.com --output report.pdf
```

### Con dominio Windows (NTLM)

```bash
python run.py --server 192.168.1.10 --username DOMAIN\\admin --output report.pdf
```

### Senza SSL (per test interni)

```bash
python run.py --server dc.local --username user@domain.local --no-ssl
```

### Export anche in JSON

```bash
python run.py --server dc.example.com --username admin@example.com --json risultati.json
```

---

## ⚙️ Opzioni

| Opzione | Descrizione |
|---------|-------------|
| `-s, --server` | Hostname o IP del Domain Controller (obbligatorio) |
| `-u, --username` | Username (user@domain o DOMAIN\\user) (obbligatorio) |
| `-p, --password` | Password (meglio usare prompt interattivo) |
| `-d, --domain` | Nome dominio (se non specificato, estratto da username) |
| `-o, --output` | File PDF di output (default: adguardian_report.pdf) |
| `--json` | Salva anche in formato JSON |
| `--no-ssl` | Usa LDAP (389) invece di LDAPS (636) |
| `--skip-cert-check` | Non verificare certificato SSL |
| `--timeout` | Timeout connessione in secondi (default: 30) |
| `--inactive-days` | Giorni per considerare account inattivo (default: 90) |

### Password sicura

La password può essere fornita tramite:
1. **Prompt interattivo** (consigliato)
2. **Variabile ambiente** `ADGUARDIAN_PASSWORD`
3. **Opzione --password** (sconsigliato)

---

## 🔍 Cosa viene analizzato

### Policy Password Dominio

| Parametro | Valore Consigliato |
|-----------|-------------------|
| Lunghezza minima | 12+ caratteri |
| Complessità | Abilitata |
| Cronologia password | 12 password |
| Scadenza massima | 90 giorni |
| Scadenza minima | 1 giorno |
| Soglia blocco account | 5 tentativi |
| Durata blocco | 15+ minuti |

### Account Utente

- **Password never expires**: Account la cui password non scade mai
- **Password not required**: Account che possono avere password vuota
- **Account inattivi**: Non loggati da X giorni
- **Password vecchie**: Non cambiate da 180+ giorni
- **Account admin**: Particolare attenzione agli account privilegiati

---

## 📊 Esempio Output

```
============================================================
RIEPILOGO AUDIT
============================================================

  Dominio: example.local
  Account analizzati: 150

  Punteggio Policy: 60/100
  Punteggio Account: 75/100
  Punteggio Complessivo: 67/100

  [!] ATTENZIONE: Trovati problemi critici!
      Consulta il report PDF per le raccomandazioni.
```

---

## 🔒 Sicurezza

- Le password non vengono mai memorizzate
- Nessun dato sensibile nei log
- Connessione LDAPS cifrata di default
- Il report non include hash o password

---

## 📄 Licenza

MIT License - Vedi file [LICENSE](LICENSE)

---

## 👨‍💻 Autore

**ISIPC - Truant Bruno**

- 🌐 Website: [isipc.com](https://isipc.com)
- 💻 GitHub: [github.com/brunotr88](https://github.com/brunotr88)

Consulente IT con oltre 14 anni di esperienza al servizio delle PMI italiane.

---

*Fatto con ❤️ in Italia per le PMI italiane*
