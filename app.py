import os
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

APP_NAME = "autoris-ots-microservice"

# Directorio donde se guardan las pruebas persistentes
PROOFS_DIR = Path(os.getenv("PROOFS_DIR", "./proofs")).resolve()
PROOFS_DIR.mkdir(parents=True, exist_ok=True)

# Flags del CLI (podés cambiarlos por env). IMPORTANTE: van ANTES del subcomando.
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

def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def _run(cmd: list[str]) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"Executable not found: {cmd[0]}. {e}")
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
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
    return r

def _run_ots_upgrade(ots_path: Path) -> dict:
    cmd = ["ots", *OTS_UPGRADE_ARGS, "upgrade", str(ots_path)]
    return _run(cmd)

# -------------------- endpoints --------------------

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
      .row{display:grid;grid-template-columns:1fr auto;gap:.75rem;align-items=end}
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

      <footer>Autoris · Microservicio de verificación · v1</footer>
    </div>
    <script>
    const $ = s => document.querySelector(s);

    // --- 1) Verificar .ots ---
    $('#f-ots').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const fd = new FormData(form);

      const otsFile = fd.get("ots_file");
      if (!otsFile || otsFile.size === 0) {
        alert("Por favor selecciona un archivo .ots");
        return;
      }

      // Si hay archivo original, pedimos al backend que guarde {hash}.ots
      const target = fd.get("target_file");
      const url = (target && target.size > 0) ? '/verify-ots?save=1' : '/verify-ots';

      const res = await fetch(url, { method:'POST', body: fd });
      const data = await res.json();

      const pre = $('#out-ots');
      pre.hidden = false;
      pre.textContent = JSON.stringify(data, null, 2);
    });

    // --- 2) Calcular SHA-256 ---
    $('#f-hash').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const res = await fetch('/hash', { method:'POST', body: fd });
      const data = await res.json();

      const pre = $('#out-hash');
      pre.hidden = false;
      pre.textContent = JSON.stringify(data, null, 2);
    });

    // --- 3) Upgrade .ots ---
    $('#f-up').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const otsFile = fd.get("ots_file");
      if (!otsFile || otsFile.size === 0) {
        alert("Por favor selecciona un archivo .ots");
        return;
      }
      // Pedimos que también la guarde en el server por hash de la .ots final
      const res = await fetch('/upgrade-ots?save=1&by_hash=1', { method:'POST', body: fd });

      // Si el server devuelve un attachment, descargamos el archivo
      const cd = res.headers.get('Content-Disposition') || '';
      if (res.ok && cd.includes('attachment')) {
        const blob = await res.blob();
        const fname = (cd.match(/filename="([^"]+)"/) || [,'upgraded.ots'])[1];
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = fname; document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);

        const pre = $('#out-up');
        pre.hidden = false;
        pre.textContent = JSON.stringify({ ok: true, detail: `Descargada ${fname}`, saved_as: res.headers.get('X-OTS-Saved-As') || null }, null, 2);
        return;
      }

      // Si no fue attachment, mostramos el JSON (p.ej. aún Pending)
      const data = await res.json();
      const pre = $('#out-up');
      pre.hidden = false;
      pre.textContent = JSON.stringify(data, null, 2);
    });

    // --- 4) Verificar por hash ---
    $('#btn-verify-hash').addEventListener('click', async () => {
      const h = $('#hash').value.trim();
      if (!h) {
        alert("Ingrese un hash SHA-256");
        return;
      }
      const res = await fetch(`/verify?file_hash=${encodeURIComponent(h)}`);
      const data = await res.json();

      const pre = $('#out-vhash');
      pre.hidden = false;
      pre.textContent = JSON.stringify(data, null, 2);
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

        # Verificar usando SOLO la .ots (el CLI detecta el original por nombre si existe)
        result = _run_ots_verify(ots_path)

        # Guardar {file_hash}.ots si lo pidieron y tenemos hash del original
        saved_as = None
        if save and file_hash:
            dest = PROOFS_DIR / f"{file_hash}.ots"
            dest.write_bytes(ots_bytes)
            saved_as = str(dest)

        return {
            "ok": result["ok"],
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
        if not r["ok"]:
            return {
                "ok": False,
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

# ⬇️ Endpoint actualizado: muestra estado "pending/complete" si no hay original
@app.get("/verify")
async def verify_by_hash(file_hash: str):
    file_hash = file_hash.lower().strip()
    if not (len(file_hash) == 64 and all(c in "0123456789abcdef" for c in file_hash)):
        raise HTTPException(status_code=400, detail="file_hash must be a 64-char hex SHA-256")

    candidate = PROOFS_DIR / f"{file_hash}.ots"
    if not candidate.exists():
        return JSONResponse(status_code=404, content={
            "ok": False,
            "detail": f"No local proof found for {file_hash}. Colocá '{file_hash}.ots' en {PROOFS_DIR} o subí vía /verify-ots?save=1.",
        })

    # 1) Intento de verificación de contenido (normalmente requeriría el archivo original)
    result = _run_ots_verify(candidate)
    if result["ok"]:
        return {
            "ok": True,
            "mode": "content_verify",
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "used_proof": str(candidate),
        }

    # 2) Sin original: devolvemos ESTADO ejecutando 'upgrade' (no valida contenido)
    up = _run_ots_upgrade(candidate)
    text = (up["stdout"] + "\n" + up["stderr"]).lower()
    status = "pending"
    if "success! timestamp complete" in text or "timestamp complete" in text:
        status = "complete"

    return {
        "ok": (status == "complete"),
        "mode": "status_only",
        "status": status,
        "returncode": up["returncode"],
        "stdout": up["stdout"],
        "stderr": up["stderr"],
        "used_proof": str(candidate),
        "note": "Sin archivo original no se verifica el contenido; solo el estado de la prueba.",
    }
