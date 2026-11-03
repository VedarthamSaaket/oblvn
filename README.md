# OBLVN

Secure Data Obliteration Platform. Military-grade data destruction for HDDs, SSDs, NVMe, and USB drives. GDPR Art. 17, HIPAA, NIST 800-88, ISO 27001 compliant. Bitcoin-anchored certificates via OpenTimestamps. Anomaly detection engine. Immutable cryptographic audit log.

---

## Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend build)
- A [MongoDB Atlas](https://www.mongodb.com/atlas) cluster (the free M0 tier is enough to start)
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

Edit `.env` and fill in at least these values.
MONGODB_URI is the connection string from Atlas (Connect, then Drivers).
OBLVN_JWT_SECRET and OBLVN_SECRET_KEY must each be 32 or more random characters, for example from python -c "import secrets; print(secrets.token_urlsafe(48))".
FIREBASE_PROJECT_ID turns on Google sign-in.
SMTP_HOST, SMTP_USER, SMTP_PASSWORD and SMTP_FROM turn on account emails; without them links are printed in the server log.

```
MONGODB_URI=mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/
OBLVN_JWT_SECRET=a-long-random-string
OBLVN_SECRET_KEY=another-long-random-string
```

**3. Set up the database**

Nothing to run by hand.
On first start OBLVN creates every collection, its validation rules and its indexes in the database named by MONGODB_DB (default oblvn).
In Atlas, allow your server's IP under Network Access.

**4. Build the frontend**

```bash
cd frontend
cp .env.example .env
# Fill in VITE_API_BASE_URL and, for Google sign-in, the four VITE_FIREBASE_* values
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
    hw/                   Disk inventory, capability probe, planner, firmware executors, overwrite, verification
    jobs.py               Job executor, completion and certificate issue
    file_wipe.py          File and folder wipes with a path allowlist
    agent_api.py          Agent pairing, heartbeat, job claim, progress and results
    wiper.py              Windows free-space fill fallback
    timestamps.py         OpenTimestamps, Bitcoin-anchored certificate proofs
    reporter.py           WeasyPrint PDF/A certificate generation
    audit.py              Cryptographically chained append-only audit log
    anomaly.py            Rule-based + statistical anomaly detection engine
    auth.py               JWT validation + role helpers
    config.py             Environment configuration
    db/                   MongoDB data layer, schema, indexes and access policies
    accounts/             Accounts: Argon2id passwords, sessions, 2FA, Google sign-in, email
  frontend/
    src/pages/            React pages (one per SRS feature)
    src/components/       Shared UI components
    src/lib/api.js        Flask API client
    src/lib/firebase.js   Firebase client for Google sign-in
    public/landing.html   Static landing page
  agent/                  Linux wipe agent and live USB build config
  ml/                     Anomaly models, training and Backblaze scripts
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

Hardware wipes run through backend/hw/pipeline.py on Linux, either in the server or in the OBLVN Linux agent.
Crypto erase uses the drive's own firmware to destroy its media key (NVMe sanitize or format, ATA sanitize crypto scramble, SCSI sanitize, or an Opal PSID revert).
If the drive has no firmware crypto erase, the job is refused instead of faked.
Binary obliteration is a software overwrite of every addressable sector using the chosen standard, and counts as NIST 800-88 Clear.
Full sanitization runs the strongest firmware purge the drive supports, then one keyed overwrite, then a read-back check.
Every random pass is an AES-256-CTR keystream, so the read-back can compare sectors exactly.
The boot disk, anything still mounted after unmount, and disks held by LVM, dm-crypt or RAID are refused.
On macOS the server can only do software overwrites, after diskutil unmountDisk, on the raw /dev/rdisk node.
On Windows a raw overwrite needs an Administrator terminal; without it OBLVN falls back to a free-space fill that is labelled as not a NIST sanitize.
File wipes are limited to OBLVN_FILE_WIPE_ROOTS (default is the invoking user's home folder) and never follow symlinks.
A job that fails or fails verification is marked failed and never gets a certificate.

---

## Anomaly Detection

Rules run in real time for logins, wipe jobs and S.M.A.R.T. data.
Each anomaly has a dedupe key so the same open issue is never written twice.
Login and off-hours checks use the organisation's timezone and working hours.
Login hour baselines use circular statistics, so 23:00 and 01:00 are two hours apart.
The nightly batch compares wipe speed per GiB per pass within the same drive type and technique.
The ML layer lives in ml/ and is trained nightly by the scheduler or by python -m ml.train.
Model A predicts wipe duration with quantile gradient boosting and flags wipes that are too fast or too slow.
Model B is an Isolation Forest per organisation for job and login behaviour, with the top reasons on every alert.
Model C is a drive failure classifier trained on the public Backblaze SMART dataset.
Model D tunes thresholds from true positive and false positive feedback sent with the acknowledge endpoint.
Trained models are saved in ml/models and raw data in ml/data, both kept out of git.

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

## IP Geolocation

Login checks use the free DB-IP Lite city and ASN databases to spot new countries, new networks and impossible travel.
Download them with python -m ml.scripts.fetch_geoip, which saves them to ml/data/geo.
IP Geolocation by DB-IP (https://db-ip.com), licensed under Creative Commons Attribution 4.0.

---

## Linux Wipe Agent

The agent runs on a Linux machine or the live USB built from agent/live/build.sh.
Create a pairing code with POST /api/agents/pairing-code and a JSON body with a name.
On the agent run sudo python3 -m agent pair --server https://your-oblvn --code XXXX-XXXX.
Then run sudo python3 -m agent run.
The agent reports its disks every 30 seconds and they show up in the Devices page.
Jobs for those disks are queued for the agent and its results come back to the server, which issues the certificate.
The live USB asks for the server and pairing code on screen the first time it boots.

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

Any account can turn on two-factor sign-in with an authenticator app (TOTP) through /api/auth/2fa/setup and /api/auth/2fa/enable.
Accounts can sign in with email and password or with Google (Firebase).

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
