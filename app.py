import os
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

APP_NAME = "autoris-ots-microservice"
PROOFS_DIR = Path(os.getenv("PROOFS_DIR", "./proofs")).resolve()
PROOFS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title=f"{APP_NAME}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def _run_ots_verify(ots_path: Path) -> dict:
    cmd = ["ots", "verify", str(ots_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="The `ots` CLI is not installed. Ensure `opentimestamps-client` is in requirements.txt")
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    ok = (proc.returncode == 0) or ("Bitcoin block" in stdout) or ("verified" in stdout.lower())
    return {"ok": bool(ok), "stdout": stdout, "stderr": stderr, "returncode": proc.returncode}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <!doctype html><html lang="es"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Autoris · Verificador OpenTimestamps</title>
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;margin:2rem;line-height:1.5}
      .card{max-width:780px;margin:auto;padding:1.25rem;border:1px solid #e5e7eb;border-radius:16px;box-shadow:0 1px 8px rgba(0,0,0,.04)}
      h1{font-size:1.5rem;margin:0 0 .75rem} h2{font-size:1.1rem;margin:1.25rem 0 .5rem}
      input[type=file],input[type=text]{width:100%;padding:.5rem;border:1px solid #d1d5db;border-radius:10px}
      button{padding:.6rem 1rem;border:0;border-radius:999px;cursor:pointer}
      .primary{background:#111827;color:#fff}.muted{background:#f3f4f6}
      .row{display:grid;grid-template-columns:1fr auto;gap:.75rem;align-items:end}
      pre{background:#0b1020;color:#d7e1ff;padding:1rem;border-radius:10px;overflow:auto}
      footer{margin-top:1rem;color:#6b7280;font-size:.9rem}
    </style>
    </head><body><div class="card">
      <h1>Verificador OpenTimestamps</h1>
      <p>Subí tu <code>.ots</code> y, si la tenés, el <b>archivo original</b> (mismo nombre que la .ots pero sin “.ots”).</p>

      <h2>1) Verificar .ots</h2>
      <form id="f-ots" enctype="multipart/form-data">
        <label>Archivo .ots</label>
        <input type="file" name="ots_file" accept=".ots" required>
        <label>Archivo original (opcional, recomendado)</label>
        <input type="file" name="target_file">
        <button class="primary" type="submit">Verificar</button>
      </form>
      <pre id="out-ots" hidden></pre>

      <h2>2) Calcular SHA-256</h2>
      <form id="f-hash" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button class="muted" type="submit">Calcular hash</button>
      </form>
      <pre id="out-hash" hidden></pre>

      <h2>3) Verificar por hash (si existe {hash}.ots en el servidor)</h2>
      <div class="row">
        <input type="text" id="hash" placeholder="Ingrese SHA-256 en hex...">
        <button class="muted" id="btn-verify-hash">Verificar</button>
      </div>
      <pre id="out-vhash" hidden></pre>

      <footer>Autoris · Microservicio de verificación · v1</footer>
    </div>
    <script>
    const $ = s => document.querySelector(s);
    $('#f-ots').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await fetch('/verify-ots', { method:'POST', body: fd });
      const data = await res.json();
      const pre = $('#out-ots'); pre.hidden=false; pre.textContent = JSON.stringify(data, null, 2);
    });
    $('#f-hash').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await fetch('/hash', { method:'POST', body: fd });
      const data = await res.json();
      const pre = $('#out-hash'); pre.hidden=false; pre.textContent = JSON.stringify(data, null, 2);
    });
    $('#btn-verify-hash').addEventListener('click', async () => {
      const h = $('#hash').value.trim(); if (!h) return;
      const res = await fetch(`/verify?file_hash=${encodeURIComponent(h)}`);
      const data = await res.json();
      const pre = $('#out-vhash'); pre.hidden=false; pre.textContent = JSON.stringify(data, null, 2);
    });
    </script></body></html>
    """

@app.post("/hash")
async def hash_file(file: UploadFile = File(...)):
    data = await file.read()
    return {"filename": file.filename, "sha256": _sha256_bytes(data), "size": len(data)}

@app.post("/verify-ots")
async def verify_ots(
    ots_file: UploadFile = File(...),
    target_file: Optional[UploadFile] = File(None),
):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        # guardar .ots
        ots_path = td / (ots_file.filename or "proof.ots")
        ots_bytes = await ots_file.read()
        ots_path.write_bytes(ots_bytes)

        file_hash = None
        # si suben el original, guardarlo con SU MISMO NOMBRE (ej: foo.png)
        if target_file is not None:
            target_bytes = await target_file.read()
            if target_bytes:
                target_save = td / (target_file.filename or "target.bin")
                target_save.write_bytes(target_bytes)
                file_hash = _sha256_bytes(target_bytes)

        # verificar SOLO con la .ots (si el original está al lado, el CLI lo encuentra)
        result = _run_ots_verify(ots_path)

        return {
            "ok": result["ok"],
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "file_hash": file_hash,
        }

@app.get("/verify")
async def verify_by_hash(file_hash: str):
    file_hash = file_hash.lower().strip()
    if not (len(file_hash) == 64 and all(c in "0123456789abcdef" for c in file_hash)):
        raise HTTPException(status_code=400, detail="file_hash must be a 64-char hex SHA-256")

    candidate = PROOFS_DIR / f"{file_hash}.ots"
    if not candidate.exists():
        return JSONResponse(status_code=404, content={
            "ok": False,
            "detail": f"No local proof found for {file_hash}. Place a matching '{file_hash}.ots' under {PROOFS_DIR} or upload via /verify-ots.",
        })

    result = _run_ots_verify(candidate)
    return {
        "ok": result["ok"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "returncode": result["returncode"],
        "used_proof": str(candidate),
    }
