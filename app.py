import os
import re
import base64
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware

APP_NAME = "autoris-ots-microservice"

# Directorio donde se guardan las pruebas persistentes
PROOFS_DIR = Path(os.getenv("PROOFS_DIR", "./proofs")).resolve()
PROOFS_DIR.mkdir(parents=True, exist_ok=True)

# Flags del CLI (podés cambiarlos por env). IMPORTANTE: van ANTES del subcomando.
# --no-bitcoin en verify evita que requiera bitcoind local; muestra estado (pending/complete).
OTS_VERIFY_ARGS = os.getenv("OTS_VERIFY_ARGS", "--no-bitcoin").split()
OTS_UPGRADE_ARGS = os.getenv("OTS_UPGRADE_ARGS", "").split()

app = FastAPI(title=f"{APP_NAME}")

# CORS abierto (ajustá si querés restringir)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- utilidades --------------------

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _run(cmd: list[str]) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"Executable not found: {cmd[0]}. {e}")
    return {
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
        "ok": proc.returncode == 0,
    }

def _run_ots_verify(ots_path: Path) -> dict:
    # Flags globales ANTES del subcomando
    cmd = ["ots", *OTS_VERIFY_ARGS, "verify", str(ots_path)]
    r = _run(cmd)
    text = (r["stdout"] + "\n" + r["stderr"]).lower()

    # Heurística de OK (aunque el returncode sea 1 por --no-bitcoin o pending)
    if ("bitcoin block" in text) or ("attestation verified" in text) or ("pending confirmation" in text) or ("got" in text and "attestation" in text):
        r["ok"] = True
    r["status"] = _status_from_text(text)
    return r

def _run_ots_upgrade(ots_path: Path) -> dict:
    cmd = ["ots", *OTS_UPGRADE_ARGS, "upgrade", str(ots_path)]
    r = _run(cmd)
    text = (r["stdout"] + "\n" + r["stderr"]).lower()
    r["status"] = _status_from_text(text)
    return r

def _run_ots_stamp(target_path: Path) -> dict:
    """Ejecuta `ots stamp <archivo>`, que genera <archivo>.ots junto al original."""
    cmd = ["ots", "stamp", str(target_path)]
    return _run(cmd)

def _status_from_text(text: str) -> str:
    t = text.lower()
    if "timestamp complete" in t or "attestation verified" in t or ("success!" in t and "complete" in t):
        return "verified"
    if "pending" in t or "pending confirmation" in t or "not enough confirmations" in t:
        return "pending"
    if "not a timestamp" in t or "error" in t or "failed" in t:
        return "failed"
    return "unknown"

# -------------------- endpoints --------------------

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def index():
    # (igual que tu versión actual: UI HTML simplificada para pruebas)
    return """
    <!doctype html><html lang="es"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Autoris · Verificador OpenTimestamps</title>
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;margin:2rem;line-height:1.5}
      .card{max-width:880px;margin:auto;padding:1.25rem;border:1px solid #e5e7eb;border-radius:16px;box-shadow:0 1px 8px rgba(0,0,0,.04)}
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

      <h2>3) Upgrade .ots (si dice Pending)</h2>
      <form id="f-up" enctype="multipart/form-data">
        <input type="file" name="ots_file" accept=".ots" required>
        <button class="muted" type="submit">Upgrade</button>
      </form>
      <pre id="out-up" hidden></pre>

      <h2>4) Verificar por hash (si existe {hash}.ots en el servidor)</h2>
      <div class="row">
        <input type="text" id="hash" placeholder="Ingrese SHA-256 en hex...">
        <button class="muted" id="btn-verify-hash">Verificar</button>
      </div>
      <pre id="out-vhash" hidden></pre>

      <h2>5) Sellar (crear .ots) — para probar</h2>
      <form id="f-stamp" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button class="muted" type="submit">Sellar y descargar .ots</button>
      </form>
      <pre id="out-stamp" hidden></pre>

      <footer>Autoris · Microservicio de verificación · v1</footer>
    </div>
    <script>
    const $ = s => document.querySelector(s);

    // 1) Verificar .ots
    $('#f-ots').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await fetch('/verify-ots?save=1', { method:'POST', body: fd });
      const data = await res.json();
      const pre = $('#out-ots'); pre.hidden = false; pre.textContent = JSON.stringify(data, null, 2);
    });

    // 2) Calcular hash
    $('#f-hash').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await fetch('/hash', { method:'POST', body: fd });
      const data = await res.json();
      const pre = $('#out-hash'); pre.hidden = false; pre.textContent = JSON.stringify(data, null, 2);
    });

    // 3) Upgrade .ots
    $('#f-up').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await fetch('/upgrade-ots?save=1&by_hash=1', { method:'POST', body: fd });
      const cd = res.headers.get('Content-Disposition') || '';
      if (res.ok && cd.includes('attachment')) {
        const blob = await res.blob();
        const fname = (cd.match(/filename="([^"]+)"/) || [,'upgraded.ots'])[1];
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = fname; document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
        const pre = $('#out-up'); pre.hidden = false;
        pre.textContent = JSON.stringify({ ok: true, detail: `Descargada ${fname}`, saved_as: res.headers.get('X-OTS-Saved-As') || null }, null, 2);
        return;
      }
      const data = await res.json();
      const pre = $('#out-up'); pre.hidden = false; pre.textContent = JSON.stringify(data, null, 2);
    });

    // 4) Verificar por hash
    $('#btn-verify-hash').addEventListener('click', async () => {
      const h = $('#hash').value.trim();
      if (!h) { alert("Ingrese un hash SHA-256"); return; }
      const res = await fetch(`/verify?file_hash=${encodeURIComponent(h)}`);
      const data = await res.json();
      const pre = $('#out-vhash'); pre.hidden = false; pre.textContent = JSON.stringify(data, null, 2);
    });

    // 5) Sellar y descargar
    $('#f-stamp').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await fetch('/stamp-file?save=1&download=1', { method:'POST', body: fd });
      const cd = res.headers.get('Content-Disposition') || '';
      if (res.ok && cd.includes('attachment')) {
        const blob = await res.blob();
        const fname = (cd.match(/filename="([^"]+)"/) || [,'proof.ots'])[1];
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = fname; document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
        const pre = $('#out-stamp'); pre.hidden = false;
        pre.textContent = JSON.stringify({ ok: true, detail: `Descargada ${fname}`, saved_as: res.headers.get('X-Saved-As') || null, file_hash: res.headers.get('X-File-Hash') || null }, null, 2);
        return;
      }
      const data = await res.json();
      const pre = $('#out-stamp'); pre.hidden = false; pre.textContent = JSON.stringify(data, null, 2);
    });
    </script></body></html>
    """

@app.post("/hash")
async def hash_file(file: UploadFile = File(...)):
    data = await file.read()
    return {"filename": file.filename, "sha256": _sha256_bytes(data), "size": len(data)}

# -------- STAMP: PDF/archivo -> OTS --------
@app.post("/stamp-file")
async def stamp_file(
    file: UploadFile = File(...),
    save: int = Query(1, description="Si =1, guarda {file_hash}.ots en PROOFS_DIR"),
    download: int = Query(0, description="Si =1, devuelve la .ots como attachment en vez de JSON"),
):
    """
    Recibe un archivo (ej: el PDF del certificado), crea su prueba OTS,
    y devuelve:
      - JSON con {file_hash, proof_b64, ots_size} (por defecto), o
      - attachment .ots si download=1.
    Si save=1, también guarda {file_hash}.ots en PROOFS_DIR.
    """
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        target_path = td / (file.filename or "target.bin")
        data = await file.read()
        target_path.write_bytes(data)

        r = _run_ots_stamp(target_path)

        proof_path = target_path.with_suffix(target_path.suffix + ".ots")
        if not proof_path.exists():
            return JSONResponse(status_code=500, content={
                "ok": False,
                "returncode": r["returncode"],
                "stdout": r["stdout"],
                "stderr": r["stderr"],
                "detail": "No se generó el archivo .ots",
            })

        proof_bytes = proof_path.read_bytes()
        file_hash = _sha256_bytes(data)

        # Guardado opcional {file_hash}.ots en PROOFS_DIR
        saved_as = None
        if save:
            dest = PROOFS_DIR / f"{file_hash}.ots"
            dest.write_bytes(proof_bytes)
            saved_as = str(dest)

        # Respuesta binaria (descarga)
        if download:
            return StreamingResponse(
                iter([proof_bytes]),
                media_type="application/octet-stream",
                headers={
                    "Content-Disposition": f'attachment; filename="{file_hash}.ots"',
                    "X-File-Hash": file_hash,
                    "X-Saved-As": saved_as or "",
                },
            )

        # JSON: base64 ESTÁNDAR con padding
        proof_b64 = base64.b64encode(proof_bytes).decode("ascii")
        return {
            "ok": True,
            "file_hash": file_hash,
            "ots_size": len(proof_bytes),
            "proof_b64": proof_b64,   # estándar + padding
            "saved_as": saved_as,
            "returncode": r["returncode"],
            "stdout": r["stdout"],
            "stderr": r["stderr"],
            "status": "pending",
        }

# Atajo: devuelve SIEMPRE la .ots en binario
@app.post("/stamp-file.raw")
async def stamp_file_raw(
    file: UploadFile = File(...),
    save: int = Query(1, description="Si =1, guarda {file_hash}.ots en PROOFS_DIR"),
):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        target_path = td / (file.filename or "target.bin")
        data = await file.read()
        target_path.write_bytes(data)

        r = _run_ots_stamp(target_path)
        proof_path = target_path.with_suffix(target_path.suffix + ".ots")
        if not proof_path.exists():
            return JSONResponse(status_code=500, content={
                "ok": False, "detail": "No se generó el archivo .ots",
                "returncode": r["returncode"], "stdout": r["stdout"], "stderr": r["stderr"],
            })

        proof_bytes = proof_path.read_bytes()
        file_hash = _sha256_bytes(data)

        if save:
            (PROOFS_DIR / f"{file_hash}.ots").write_bytes(proof_bytes)

        return Response(
            content=proof_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{file_hash}.ots"'}
        )

@app.post("/verify-ots")
async def verify_ots(
    ots_file: UploadFile = File(...),
    target_file: Optional[UploadFile] = File(None),
    save: int = Query(0, description="Si =1, guarda la prueba como {file_hash}.ots (requiere archivo original)"),
):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        # Guardar .ots temporal
        ots_path = td / (ots_file.filename or "proof.ots")
        ots_bytes = await ots_file.read()
        ots_path.write_bytes(ots_bytes)

        # Si viene el archivo original, guardarlo con su nombre para que el CLI lo encuentre automáticamente
        file_hash = None
        if target_file is not None:
            target_bytes = await target_file.read()
            if target_bytes:
                (td / (target_file.filename or "target.bin")).write_bytes(target_bytes)
                file_hash = _sha256_bytes(target_bytes)

        result = _run_ots_verify(ots_path)

        # Guardar {file_hash}.ots si lo pidieron y tenemos hash del original
        saved_as = None
        if save and file_hash:
            dest = PROOFS_DIR / f"{file_hash}.ots"
            dest.write_bytes(ots_bytes)
            saved_as = str(dest)

        return {
            "ok": (result["status"] == "verified"),
            "status": result["status"],
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "file_hash": file_hash,
            "saved_as": saved_as,
        }

@app.post("/upgrade-ots")
async def upgrade_ots(
    ots_file: UploadFile = File(...),
    save: int = Query(0, description="Si =1, guarda la .ots mejorada en PROOFS_DIR"),
    by_hash: int = Query(1, description="Si save=1 y by_hash=1, nombre {sha256(ots)}.ots"),
):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        ots_path = td / (ots_file.filename or "proof.ots")
        ots_bytes = await ots_file.read()
        ots_path.write_bytes(ots_bytes)

        r = _run_ots_upgrade(ots_path)
        upgraded = ots_path.read_bytes()
        filename = ots_file.filename or "proof.ots"

        # Guardado opcional en servidor
        saved_as = None
        if save:
            out_name = filename
            if by_hash:
                out_name = f"{_sha256_bytes(upgraded)}.ots"
            dest = PROOFS_DIR / out_name
            dest.write_bytes(upgraded)
            saved_as = str(dest)

        # Si aún está pending, devolvemos JSON
        if r["status"] != "verified":
            return {
                "ok": False,
                "status": r["status"],
                "returncode": r["returncode"],
                "stdout": r["stdout"],
                "stderr": r["stderr"],
                "ots_size": len(upgraded),
                "saved_as": saved_as,
            }

        # Si mejoró OK, devolvemos archivo como descarga
        return StreamingResponse(
            iter([upgraded]),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-OTS-ReturnCode": str(r["returncode"]),
                "X-OTS-Saved-As": saved_as or "",
            },
        )

@app.get("/verify")
async def verify_by_hash(file_hash: str):
    file_hash = file_hash.lower().strip()
    if not HEX64_RE.match(file_hash):
        raise HTTPException(status_code=400, detail="file_hash must be a 64-char hex SHA-256")

    candidate = PROOFS_DIR / f"{file_hash}.ots"
    if not candidate.exists():
        return JSONResponse(status_code=404, content={
            "ok": False,
            "detail": f"No local proof found for {file_hash}. Colocá '{file_hash}.ots' en {PROOFS_DIR} o subí vía /verify-ots?save=1.",
        })

    # 1) Intento de verificación de contenido (sin original puede fallar)
    result = _run_ots_verify(candidate)
    if result["status"] == "verified":
        return {
            "ok": True,
            "status": "verified",
            "mode": "content_verify",
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "used_proof": str(candidate),
        }

    # 2) Sin original: devolvemos ESTADO ejecutando 'upgrade' (status only)
    up = _run_ots_upgrade(candidate)
    return {
        "ok": (up["status"] == "verified"),
        "status": up["status"],
        "mode": "status_only",
        "returncode": up["returncode"],
        "stdout": up["stdout"],
        "stderr": up["stderr"],
        "used_proof": str(candidate),
        "note": "Sin archivo original no se verifica el contenido; solo el estado de la prueba.",
    }
