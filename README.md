# OBLVN

Secure Data Obliteration Platform. Military-grade data destruction for HDDs, SSDs, NVMe, and USB drives. GDPR Art. 17, HIPAA, NIST 800-88, ISO 27001 compliant. Bitcoin-anchored certificates via OpenTimestamps. Anomaly detection engine. Immutable cryptographic audit log.

---

## Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend build)
- A [Supabase](https://supabase.com) project (free tier is sufficient)
- Physical storage drives connected (or use `--dry-run` for development)
- Elevated privileges: `sudo` on Linux/macOS, Administrator on Windows

---

## Quick Start

**1. Clone and install**

```bash
git clone https://github.com/your-org/oblvn.git
cd oblvn
pip install -r requirements.txt
```

**2. Configure environment**

```bash
cp .env.example .env
```

Edit `.env` and fill in your Supabase credentials from your Supabase dashboard under Settings > API:

```
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
FLASK_SECRET_KEY=any-long-random-string
```

**3. Set up the database**

In your Supabase dashboard, go to the SQL Editor and run the contents of `supabase/schema.sql`. This creates all tables, RLS policies, triggers, and enables Realtime for wipe job progress.

**4. Build the frontend**

```bash
cd frontend
cp .env.example .env
# Fill in VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY
npm install
npm run build
cd ..
```

**5. Run**

```bash
python run.py
```

The app opens at `http://localhost:5173`. The landing page is at `/`, the app is at `/app`.

For development without physical drives:

```bash
python run.py --dry-run
```

---

## Architecture

```
oblvn/
  run.py                  Launcher, starts Flask + opens browser
  backend/
    server.py             Flask REST API + Flask-SocketIO
    detector.py           Cross-platform device enumeration + S.M.A.R.T.
    wiper.py              Binary overwrite engine (DoD, Gutmann, NIST)
    crypto_erase.py       AES-256-CBC encryption + ctypes.memset key destruction
    sanitizer.py          Full sanitization orchestrator
    timestamps.py         OpenTimestamps, Bitcoin-anchored certificate proofs
    reporter.py           WeasyPrint PDF/A certificate generation
    audit.py              Cryptographically chained append-only audit log
    anomaly.py            Rule-based + statistical anomaly detection engine
    auth.py               JWT validation + role helpers
    config.py             Environment configuration
    supabase_client.py    Supabase client singletons
  frontend/
    src/pages/            React pages (one per SRS feature)
    src/components/       Shared UI components
    src/lib/api.js        Flask API client
    src/lib/supabase.js   Supabase client
    public/landing.html   Static landing page
  supabase/
    schema.sql            PostgreSQL schema, RLS policies, triggers
  tests/
    unit/                 Unit tests per backend module
    integration/          API integration tests
  docker/
    Dockerfile
    docker-compose.yml
    nginx.conf
```

---

## Wipe Methods

| Method | Description | Best For |
|---|---|---|
| Binary Obliteration | Multi-pass overwrite. DoD 5220.22-M (3 pass), Gutmann (35 pass), or NIST 800-88 (1 pass) | HDDs |
| Crypto Erasure | AES-256-CBC encrypt then destroy key via ctypes.memset. Key shown once, never stored | SSDs, NVMe |
| Full Sanitization | Overwrite passes + crypto seal + sector verification + certificate | All types, highest assurance |

---

## Anomaly Detection

Two-layer engine runs on every relevant event and nightly in batch:

**Rule-based layer (real-time)**
- Brute-force login detection (configurable failed-login threshold per org)
- New IP address login alert
- Unusual login hour detection
- Role escalation detection
- Wipe verification failure (critical)
- Off-hours wipe submission
- Repeat wipe of same device within configurable window
- New operator first wipe flag
- S.M.A.R.T. triggers: reallocated sectors, temperature over 55C, power-on hours over 50,000, FAILED attributes

**Statistical layer (nightly batch)**
- Z-score analysis on wipe job durations
- Switches from seeded baseline to real data after 30 events

Anomalies are written to a dedicated `anomalies` table and flagged in the audit log. Org Admin and Team Lead can acknowledge, add notes, and mark resolved. Risk score (0-100) shown on dashboard.

**Sensitivity levels (per org)**
- Low: permissive thresholds, fewer alerts
- Medium: default
- High: strict thresholds, maximum detection

---

## Certificate of Destruction

Every completed wipe produces a PDF/A certificate containing:
- Certificate UUID (format: job-id)
- Device serial, model, capacity, type
- S.M.A.R.T. snapshot captured pre-wipe
- Wipe method and standard applied
- Pass count and verification result
- Operator identity and approver (if applicable)
- SHA-256 hash of all certificate fields
- OpenTimestamps proof, Bitcoin-anchored

**Three-layer verification:**
1. Self-verify: recompute SHA-256 from the certificate fields
2. Server-verify: `GET /verify/{certificate_id}`
3. Blockchain-verify: run `ots verify certificate.ots` using the attached `.ots` file

---

## OpenTimestamps

OBLVN uses [OpenTimestamps](https://opentimestamps.org) for certificate anchoring. It is completely free, requires no wallet, and anchors SHA-256 hashes to the Bitcoin blockchain.

After running a wipe, a `.ots` proof file is saved to `~/.oblvn/ots/{cert-id}.ots`. The proof is pending until a Bitcoin block confirms (usually under 1 hour). To upgrade and verify:

```bash
pip install opentimestamps-client
ots upgrade ~/.oblvn/ots/{cert-id}.ots
ots verify ~/.oblvn/ots/{cert-id}.ots
```

---

## Organisation Tier

Create an organisation from the Organisation page. Then:
- Invite members by email, assign roles (Org Admin, Team Lead, Operator)
- Enable the approval gate: Operator wipe jobs enter Pending Approval and require Team Lead or Org Admin sign-off before execution
- Configure anomaly detection sensitivity (Low / Medium / High)
- Configure audit log retention period (default 7 years, HIPAA minimum)
- Export audit log as PDF, CSV, or JSON for compliance submissions

---

## Roles

| Role | Can Do |
|---|---|
| Individual | Own jobs, own certificates, own audit entries |
| Operator | Own jobs within org, cannot delete audit records |
| Team Lead | Approve/reject operator jobs, see team jobs and anomalies |
| Org Admin | Full org access, billing, settings, member management, all audit logs |

All org roles require 2FA via Supabase MFA.

---

## Docker Deployment

```bash
cd docker
docker-compose up -d
```

The app is available at `http://localhost`. For HTTPS, place your certificates in `docker/certs/` and update `nginx.conf` with SSL directives.

---

## Development

**Run tests**

```bash
pytest
```

**Install pre-commit hooks**

```bash
pip install pre-commit
pre-commit install
```

**Lint**

```bash
ruff check backend/
ruff format backend/
```

**Frontend dev server**

```bash
cd frontend
npm run dev
```

The Vite dev server proxies `/api` and `/verify` to the Flask backend at `localhost:5173`.

---

## Compliance References

- GDPR Art. 17 (Right to Erasure), Art. 5(1)(c) (Data Minimisation), Art. 24, Art. 32
- HIPAA 45 CFR §164.308(a)(3), §164.308(a)(5)(ii)(D), §164.310(d)(2)(i), §164.312(b), §164.312(d)
- NIST SP 800-88 Rev. 1 (Purge category for all supported device types)
- DoD 5220.22-M (National Industrial Security Program Operating Manual)
- ISO/IEC 27001:2022 (A.8.10 Information deletion)
- SOC 2 Type II (CC6.5 Logical and physical access controls)
- FIPS 140-2 (AES-256-CBC via PyCryptodome)

---

## License

MIT. See LICENSE.
