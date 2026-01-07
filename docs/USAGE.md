# Guida all'uso di ADGuardian

## Indice
1. [Introduzione](#introduzione)
2. [Requisiti](#requisiti)
3. [Installazione](#installazione)
4. [Primo Audit](#primo-audit)
5. [Interpretare il Report](#interpretare-il-report)
6. [Casi d'Uso Comuni](#casi-duso-comuni)
7. [Risoluzione Problemi](#risoluzione-problemi)

---

## Introduzione

ADGuardian è uno strumento di audit per verificare la sicurezza delle password nel tuo dominio Active Directory. È pensato per:

- **Titolari di PMI**: Capire se le password aziendali sono sicure
- **IT Manager**: Verificare la configurazione AD
- **Consulenti**: Generare report per i clienti

### Cosa analizza?

1. **Policy Password Dominio**: Le regole che gli utenti devono seguire
2. **Account Utente**: Configurazioni pericolose sui singoli account

---

## Requisiti

### Sistema
- Python 3.8 o superiore
- Windows, Linux o macOS

### Rete
- Connettività al Domain Controller (LDAP 389 o LDAPS 636)
- Credenziali con permessi di lettura AD

### Permessi Minimi
L'utente usato per l'audit deve poter:
- Leggere oggetti in Active Directory
- Accedere alle policy del dominio

Un utente normale del dominio solitamente ha questi permessi.

---

## Installazione

```bash
# Clona il repository
git clone https://github.com/brunotr88/adguardian.git
cd adguardian

# Crea virtual environment (opzionale ma consigliato)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# oppure: venv\Scripts\activate  # Windows

# Installa dipendenze
pip install -r requirements.txt
```

### Verifica installazione

```bash
python run.py --version
```

Dovrebbe mostrare: `ADGuardian v1.0.0 - ISIPC - Truant Bruno`

---

## Primo Audit

### 1. Identifica il Domain Controller

Il Domain Controller è il server che gestisce Active Directory. Puoi trovarlo:

**Windows (da un PC nel dominio)**:
```cmd
echo %LOGONSERVER%
```

**Oppure con nslookup**:
```cmd
nslookup -type=srv _ldap._tcp.DOMINIO.LOCAL
```

### 2. Prepara le credenziali

Avrai bisogno di:
- Username: `utente@dominio.local` oppure `DOMINIO\utente`
- Password

### 3. Esegui l'audit

```bash
python run.py --server dc.dominio.local --username admin@dominio.local
```

Ti verrà chiesta la password in modo sicuro (non viene mostrata).

### 4. Risultato

Verrà generato `adguardian_report.pdf` con i risultati.

---

## Interpretare il Report

### Punteggio (0-100)

- **80-100**: Configurazione adeguata
- **60-79**: Migliorabile, alcuni problemi
- **40-59**: Carenze significative
- **0-39**: Problemi gravi, intervento urgente

### Semaforo

- 🔴 **CRITICO**: Problema grave, agire subito
- 🟡 **ATTENZIONE**: Da verificare/correggere
- 🟢 **OK**: Configurazione corretta

### Sezione Policy

Verifica le impostazioni del dominio. Problemi comuni:

| Problema | Rischio | Soluzione |
|----------|---------|-----------|
| Lunghezza < 8 | Password facilmente violabili | Aumentare a 12+ |
| Complessità disabilitata | Password banali permesse | Abilitare |
| Password mai scadono | Compromissione permanente | Impostare 90 giorni |
| No blocco account | Attacchi brute-force | Impostare 5 tentativi |

### Sezione Account

Verifica i singoli utenti. Problemi comuni:

| Problema | Rischio | Soluzione |
|----------|---------|-----------|
| Password never expires | Se compromesso, mai scade | Rimuovere flag |
| Password not required | Account senza password | Rimuovere flag |
| Account inattivo | Potenziale vettore attacco | Disabilitare |

---

## Casi d'Uso Comuni

### Audit rapido senza SSL

Per test in rete interna senza LDAPS:

```bash
python run.py --server 192.168.1.10 --username admin@domain.local --no-ssl
```

### Export JSON per automazione

```bash
python run.py --server dc.local --username admin@domain.local \
  --output report.pdf --json dati.json
```

### Soglia personalizzata per inattività

Account inattivi da 180 giorni invece che 90:

```bash
python run.py --server dc.local --username admin@domain.local \
  --inactive-days 180
```

### Password da variabile ambiente

```bash
export ADGUARDIAN_PASSWORD="mia_password"
python run.py --server dc.local --username admin@domain.local
```

---

## Risoluzione Problemi

### "Connessione fallita"

1. Verifica che il server sia raggiungibile: `ping dc.dominio.local`
2. Verifica porta aperta: `telnet dc.dominio.local 636` (o 389)
3. Prova con `--no-ssl` se LDAPS non è configurato

### "Credenziali non valide"

1. Verifica formato username: `utente@dominio.local` o `DOMINIO\utente`
2. Verifica la password
3. Verifica che l'account non sia bloccato

### "Permesso negato"

L'utente non ha permessi sufficienti. Prova con un utente admin o chiedi all'amministratore di dominio.

### "Timeout"

Il server non risponde in tempo. Aumenta il timeout:

```bash
python run.py --server dc.local --username admin@domain.local --timeout 60
```

### Errore certificato SSL

Se il certificato del DC non è valido:

```bash
python run.py --server dc.local --username admin@domain.local --skip-cert-check
```

⚠️ Non usare in produzione, solo per test.

---

## Supporto

- 🌐 Website: [isipc.com](https://isipc.com)
- 💻 GitHub Issues: [github.com/brunotr88/adguardian/issues](https://github.com/brunotr88/adguardian/issues)

---

*Sviluppato da ISIPC - Truant Bruno | https://isipc.com*
