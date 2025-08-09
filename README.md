# Autoris OTS Microservice (Render)

### What this does
- Verifies OpenTimestamps proofs (`.ots`) against Bitcoin using the official CLI.
- Minimal HTML UI at `/` for quick manual checks.
- API suitable for Make/Airtable automations.

### Endpoints
- `GET /health` → health check.
- `POST /hash` (multipart) → returns SHA-256 of an uploaded file.
- `POST /verify-ots` (multipart) → fields: `ots_file` (required), `target_file` (optional). Returns CLI output and status.
- `GET /verify?file_hash=...` → looks for a local proof named `{hash}.ots` under `PROOFS_DIR` and verifies it.

### Deploy on Render (quick)
1) Create a new repo with these files and push to GitHub.
2) In Render → New → Web Service → Connect Repo → Python.
3) Build command: `pip install -r requirements.txt`
4) Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
5) (Optional) Set `PROOFS_DIR` env var. Render’s disk is ephemeral; consider Render Disks if you need persistence.

### Using from Make (Integromat)
- **Verify after generation**: Once your flow creates a `.ots`, call `POST /verify-ots` with the proof file and, if available, the original file bytes. Store the response (`ok`, `stdout`) in Airtable.
- **Hash-only check**: If you store proofs as `{sha256}.ots` in a known bucket you sync to `PROOFS_DIR`, you can hit `GET /verify?file_hash=...` directly.

### Notes & limitations
- Verifying requires a proof; a raw hash alone isn’t sufficient unless you already have a matching `.ots`.
- The service uses the `ots` CLI; you can run the same commands locally to compare behavior.
- For long-term storage, wire `PROOFS_DIR` to a persistent disk or sync from cloud storage on boot.

### Local dev
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

### License
MIT
