#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PS-Signer – Small Windows Python application with GUI for signing PowerShell scripts.

Requirements
  - Windows with Windows PowerShell 5.1 (powershell.exe) or PowerShell 7 (pwsh.exe)
  - Python 3.9+ (tkinter is included in the official Windows installer)
  - pip install "cryptography>=39"

Usage
  python ps_signer.py

How it works
  Certificate and private key are loaded and validated in Python and combined into a
  temporary PFX encrypted with a random password (the password is passed to the
  child process via an environment variable only). PowerShell then signs using
  Set-AuthenticodeSignature:
    - PowerShell 7:   Get-PfxCertificate -Password, no certificate store involved
    - PowerShell 5.1: temporary import into CurrentUser\\My, removed afterwards
  The PowerShell code is compatible with Constrained Language Mode (AppLocker/WDAC).

Settings: %USERPROFILE%\\.ps-signer\\settings.json  (passwords are NEVER stored)
"""

import base64
import codecs
import datetime as dt
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID
except ImportError:  # pragma: no cover
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror("Missing package",
                         "The package 'cryptography' is missing.\n\npip install cryptography")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
APP_NAME = "PS-Signer"
APP_VERSION = "1.3"
APP_AUTHOR = "Steffen Jahn"
CONFIG_DIR = Path.home() / ".ps-signer"          # C:\Users\<username>\.ps-signer
CONFIG_FILE = CONFIG_DIR / "settings.json"

HEADER_BEGIN = "# --- Signing Header ---"
HEADER_END = "# --- End Signing Header ---"
# Markers of older versions, so old headers are replaced when re-signing
HEADER_MARKERS = [(HEADER_BEGIN, HEADER_END),
                  (HEADER_BEGIN, "# --- Ende Signing Header ---"),
                  ("# --- PS-Signer Header ---", "# --- Ende PS-Signer Header ---")]
SIG_BEGIN = "# SIG # Begin signature block"

SCRIPT_EXT = {".ps1", ".psm1", ".psd1", ".ps1xml"}
HEADER_EXT = {".ps1", ".psm1", ".psd1"}          # .ps1xml is XML -> no # comments
PFX_EXT = {".pfx", ".p12"}

CERT_TYPES = [("Certificates", "*.pfx *.p12 *.pem *.cer *.crt"), ("All files", "*.*")]
KEY_TYPES = [("Private keys", "*.pem *.key *.pfx *.p12"), ("All files", "*.*")]
SCRIPT_TYPES = [("PowerShell", "*.ps1 *.psm1 *.psd1 *.ps1xml"), ("All files", "*.*")]

TS_SERVERS = [
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
    "",
]


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
@dataclass
class Settings:
    cert_path: str = ""
    key_path: str = ""
    script_dir: str = ""
    script_files: list = field(default_factory=list)
    author_name: str = ""
    author_email: str = ""
    timestamp_server: str = "http://timestamp.digicert.com"
    hash_algorithm: str = "SHA256"
    powershell_exe: str = "powershell.exe"

    @classmethod
    def load(cls) -> "Settings":
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return cls(**data)
        except FileNotFoundError:
            return cls()
        except Exception as exc:  # broken file -> defaults
            print(f"Could not read settings: {exc}", file=sys.stderr)
            return cls()

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False),
                               encoding="utf-8")


# --------------------------------------------------------------------------- #
# Certificates & keys
# --------------------------------------------------------------------------- #
def is_pfx(path: str) -> bool:
    return Path(path).suffix.lower() in PFX_EXT


def _pw(password: str):
    return password.encode("utf-8") if password else None


def load_private_key(key_path: str, password: str):
    """Loads a private key from PEM, DER or PFX."""
    data = Path(key_path).read_bytes()
    if is_pfx(key_path):
        key, _, _ = pkcs12.load_key_and_certificates(data, _pw(password))
        if key is None:
            raise ValueError("The PFX file does not contain a private key.")
        return key
    loader = (serialization.load_pem_private_key if b"-----BEGIN" in data
              else serialization.load_der_private_key)
    pw = _pw(password)
    try:
        return loader(data, password=pw)
    except TypeError:
        # password given but key not encrypted -> retry without password
        if pw is not None:
            return loader(data, password=None)
        raise ValueError("The private key is encrypted – please enter the password.")


def load_material(cert_path: str, key_path: str, password: str):
    """Returns (certificate, private key or None, chain)."""
    data = Path(cert_path).read_bytes()
    key = None
    if is_pfx(cert_path):
        key, cert, chain = pkcs12.load_key_and_certificates(data, _pw(password))
        if cert is None:
            raise ValueError("The PFX file does not contain a certificate.")
        chain = list(chain or [])
    elif b"-----BEGIN CERTIFICATE-----" in data:
        certs = x509.load_pem_x509_certificates(data)
        cert, chain = certs[0], certs[1:]
    else:
        cert, chain = x509.load_der_x509_certificate(data), []
    if key_path:
        key = load_private_key(key_path, password)
    return cert, key, chain


def _spki(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def key_matches_cert(key, cert) -> bool:
    return _spki(key.public_key()) == _spki(cert.public_key())


def has_code_signing_eku(cert) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return ExtendedKeyUsageOID.CODE_SIGNING in eku
    except x509.ExtensionNotFound:
        return False


def _utc(cert, name: str) -> dt.datetime:
    value = getattr(cert, name + "_utc", None)          # cryptography >= 42
    if value is None:
        value = getattr(cert, name).replace(tzinfo=dt.timezone.utc)
    return value


def cert_validity(cert):
    now = dt.datetime.now(dt.timezone.utc)
    nb, na = _utc(cert, "not_valid_before"), _utc(cert, "not_valid_after")
    if now < nb:
        return False, "not yet valid"
    if now > na:
        return False, "EXPIRED"
    return True, f"valid ({(na - now).days} days remaining)"


def describe_public_key(pub) -> str:
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size} bit"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECC {pub.curve.name} ({pub.key_size} bit)"
    return f"{type(pub).__name__} (not suitable for Authenticode)"


def format_rows(rows) -> str:
    width = max(len(label) for label, _ in rows) + 2
    return "\n".join(f"{(label + ':').ljust(width)} {value}" for label, value in rows)


def local_time(value: dt.datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def cert_info_text(cert, chain=()) -> str:
    _, status = cert_validity(cert)
    sig_hash = getattr(cert.signature_hash_algorithm, "name", "?")
    rows = [
        ("Subject", cert.subject.rfc4514_string()),
        ("Issuer", cert.issuer.rfc4514_string()),
        ("Self-signed", "yes" if cert.subject == cert.issuer else "no"),
        ("Serial number", format(cert.serial_number, "X")),
        ("Valid from", local_time(_utc(cert, "not_valid_before"))),
        ("Valid until", local_time(_utc(cert, "not_valid_after"))),
        ("Status", status),
        ("Thumbprint (SHA1)", cert.fingerprint(hashes.SHA1()).hex().upper()),
        ("Fingerprint (SHA256)", cert.fingerprint(hashes.SHA256()).hex().upper()),
        ("Signature hash", sig_hash.upper()),
        ("Public key", describe_public_key(cert.public_key())),
        ("Public key SHA256", hashlib.sha256(_spki(cert.public_key())).hexdigest().upper()),
    ]
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        names = {"digital_signature": "Digital signature",
                 "content_commitment": "Non-repudiation",
                 "key_encipherment": "Key encipherment",
                 "data_encipherment": "Data encipherment",
                 "key_agreement": "Key agreement",
                 "key_cert_sign": "Certificate signing",
                 "crl_sign": "CRL signing"}
        rows.append(("Key usage",
                     ", ".join(v for k, v in names.items() if getattr(ku, k)) or "-"))
    except x509.ExtensionNotFound:
        rows.append(("Key usage", "(not specified)"))
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        rows.append(("Extended key usage",
                     ", ".join(getattr(o, "_name", o.dotted_string) for o in eku)))
    except x509.ExtensionNotFound:
        rows.append(("Extended key usage", "(not specified)"))
    rows.append(("Code signing allowed",
                 "YES" if has_code_signing_eku(cert)
                 else "NO – not suitable for PowerShell signatures"))

    text = format_rows(rows)
    if chain:
        text += "\n\nAdditional certificates in file (chain):\n"
        text += "\n".join(f"  - {c.subject.rfc4514_string()}" for c in chain)
    return text


def key_info_text(key, cert=None) -> str:
    pub = key.public_key()
    rows = [("Key type", describe_public_key(pub)),
            ("Public key SHA256", hashlib.sha256(_spki(pub)).hexdigest().upper())]
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        rows.append(("Warning", "RSA < 2048 bit is considered insecure"))
    if cert is None:
        rows.append(("Matches certificate", "(no certificate loaded)"))
    else:
        rows.append(("Matches certificate",
                     "YES" if key_matches_cert(key, cert) else "NO – wrong key!"))
        rows.append(("Certificate", cert.subject.rfc4514_string()))
    return format_rows(rows)


def build_pfx(cert, key):
    """Creates an in-memory PFX with a random password -> (bytes, password).

    The chain is intentionally not embedded so that Import-PfxCertificate does not
    leave CA certificates behind in the "Personal" store.
    """
    password = secrets.token_urlsafe(24)
    try:
        # 3DES/SHA1 for maximum compatibility with Import-PfxCertificate
        enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
               .kdf_rounds(50000)
               .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
               .hmac_hash(hashes.SHA1())
               .build(password.encode()))
    except Exception:
        enc = serialization.BestAvailableEncryption(password.encode())
    data = pkcs12.serialize_key_and_certificates(b"PS-Signer", key, cert, None, enc)
    return data, password


def thumbprint(cert) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()


# --------------------------------------------------------------------------- #
# Script files
# --------------------------------------------------------------------------- #
_BOMS = ((codecs.BOM_UTF8, "utf-8-sig"),
         (codecs.BOM_UTF16_LE, "utf-16"),
         (codecs.BOM_UTF16_BE, "utf-16"))


def read_script(path: str):
    raw = Path(path).read_bytes()
    for bom, enc in _BOMS:
        if raw.startswith(bom):
            return raw.decode(enc), enc
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("cp1252"), "cp1252"


def encoding_warning(path: str):
    raw = Path(path).read_bytes()
    if raw.startswith(tuple(b for b, _ in _BOMS)) or raw.isascii():
        return None
    return ("File without BOM containing non-ASCII characters – Windows PowerShell 5.1 "
            "may misread them. Recommendation: save as UTF-8 with BOM.")


def apply_header(path: str, settings: Settings, cert) -> str:
    """Inserts/updates the signing header. Returns a note if applicable."""
    text, enc = read_script(path)
    nl = "\r\n" if "\r\n" in text else "\n"

    # Remove old signature (it would be invalid after the change anyway)
    idx = text.find(SIG_BEGIN)
    if idx != -1:
        text = text[:idx].rstrip("\r\n") + nl

    # Remove existing headers (including those from older versions)
    for begin, stop in HEADER_MARKERS:
        b, e = text.find(begin), text.find(stop)
        if b != -1 and e > b:
            end = text.find("\n", e)
            text = text[:b] + (text[end + 1:] if end != -1 else "")

    thumb = thumbprint(cert)
    lines = [HEADER_BEGIN]
    if settings.author_name:
        lines.append(f"# Name:        {settings.author_name}")
    if settings.author_email:
        lines.append(f"# Email:       {settings.author_email}")
    lines.append(f"# Signed on:   {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"# Certificate: {cert.subject.rfc4514_string()}")
    lines.append(f"# Thumbprint:  {thumb}")
    lines.append(HEADER_END)
    text = nl.join(lines) + nl + text

    note = ""
    if enc == "utf-8" and not text.isascii():
        enc = "utf-8-sig"
        note = "saved as UTF-8 with BOM"
    with open(path, "w", encoding=enc, newline="") as fh:
        fh.write(text)
    return note


# --------------------------------------------------------------------------- #
# PowerShell
# --------------------------------------------------------------------------- #
# The scripts are compatible with "Constrained Language Mode" (AppLocker/WDAC):
# no .NET method calls, no property setters, no type constructors –
# only cmdlets, hashtables and property reads. Results are returned via a
# UTF-8 file so the console encoding does not matter.
PS_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$job  = Get-Content -LiteralPath $env:PSSIGNER_JOB -Raw -Encoding UTF8 | ConvertFrom-Json
$mode = [string]$ExecutionContext.SessionState.LanguageMode
$cleanup = ''
"""

PS_OUTPUT = r"""
$out = @{ mode = $mode; cleanup = $cleanup; results = @($results) }
ConvertTo-Json -InputObject $out -Depth 5 -Compress | Set-Content -LiteralPath $job.out -Encoding UTF8
"""

PS_SIGN = PS_PREAMBLE + r"""
$sec = ConvertTo-SecureString -String $env:PSSIGNER_PW -AsPlainText -Force
$storePath = 'Cert:\CurrentUser\My\' + $job.thumbprint
$imported = $false
try {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # PowerShell 7: certificate straight from the PFX, no certificate store needed
        $cert = Get-PfxCertificate -FilePath $job.pfx -Password $sec
    } else {
        # Windows PowerShell 5.1: temporarily import into CurrentUser\My
        if (-not (Test-Path -LiteralPath $storePath)) {
            $null = Import-PfxCertificate -FilePath $job.pfx -CertStoreLocation 'Cert:\CurrentUser\My' -Password $sec
            $imported = $true
        }
        $cert = Get-Item -LiteralPath $storePath
        if (-not $cert.HasPrivateKey) {
            throw ('Certificate ' + $job.thumbprint + ' already exists WITHOUT a private key in CurrentUser\My. Please remove it there (certmgr.msc).')
        }
    }
    $results = foreach ($f in $job.files) {
        try {
            if ($job.timestamp) {
                $p = @{ LiteralPath = $f; Certificate = $cert; HashAlgorithm = $job.hash; IncludeChain = 'NotRoot'; TimestampServer = $job.timestamp }
            } else {
                $p = @{ LiteralPath = $f; Certificate = $cert; HashAlgorithm = $job.hash; IncludeChain = 'NotRoot' }
            }
            $s = Set-AuthenticodeSignature @p
            @{ path = $f; status = [string]$s.Status; message = [string]$s.StatusMessage }
        } catch {
            @{ path = $f; status = 'Error'; message = [string]$_.Exception.Message }
        }
    }
} finally {
    if ($imported) {
        Remove-Item -LiteralPath $storePath -DeleteKey -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $storePath) { $cleanup = 'failed' } else { $cleanup = 'ok' }
    }
}
""" + PS_OUTPUT

PS_VERIFY = PS_PREAMBLE + r"""
$results = foreach ($f in $job.files) {
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $f
        $signer = ''; $thumb = ''; $until = ''; $ts = ''
        if ($s.SignerCertificate) {
            $signer = [string]$s.SignerCertificate.Subject
            $thumb  = [string]$s.SignerCertificate.Thumbprint
            $until  = Get-Date -Date $s.SignerCertificate.NotAfter -Format 'yyyy-MM-dd'
        }
        if ($s.TimeStamperCertificate) { $ts = [string]$s.TimeStamperCertificate.Subject }
        @{ path = $f; status = [string]$s.Status; message = [string]$s.StatusMessage;
           signer = $signer; thumbprint = $thumb; valid_until = $until; timestamper = $ts }
    } catch {
        @{ path = $f; status = 'Error'; message = [string]$_.Exception.Message }
    }
}
""" + PS_OUTPUT


def decode_console(raw: bytes) -> str:
    """Decodes PowerShell output (UTF-8, otherwise OEM code page such as cp850)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    codepage = "cp850"
    if os.name == "nt":
        try:
            import ctypes
            codepage = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            pass
    return raw.decode(codepage, errors="replace")


def clean_ps_error(text: str) -> str:
    """Turns CLIXML error output into readable text."""
    if "#< CLIXML" not in text:
        return text.strip()
    parts = re.findall(r'<S S="Error">(.*?)</S>', text, re.S)
    msg = "".join(parts)
    msg = re.sub(r"_x([0-9A-Fa-f]{4})_", lambda m: chr(int(m.group(1), 16)), msg)
    return html.unescape(msg).strip()


def run_powershell(settings: Settings, script: str, files, job_extra=None,
                   secret_env=None, pfx_bytes=None):
    """Runs a PS script -> (language mode, results, cleanup status)."""
    tmp = tempfile.mkdtemp(prefix="pssigner_")
    job_path = os.path.join(tmp, "job.json")
    out_path = os.path.join(tmp, "result.json")
    job = {"files": list(files), "out": out_path, **(job_extra or {})}
    data = None
    try:
        if pfx_bytes is not None:
            pfx_path = os.path.join(tmp, "cert.pfx")        # encrypted with random password
            with open(pfx_path, "wb") as fh:
                fh.write(pfx_bytes)
            job["pfx"] = pfx_path
        with open(job_path, "w", encoding="utf-8") as fh:
            json.dump(job, fh, ensure_ascii=False)

        env = os.environ.copy()
        env["PSSIGNER_JOB"] = job_path
        env.update(secret_env or {})
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        cmd = [settings.powershell_exe or "powershell.exe", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
        proc = subprocess.run(cmd, capture_output=True, env=env, timeout=900,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if os.path.isfile(out_path):
            data = json.loads(Path(out_path).read_text(encoding="utf-8-sig"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if proc.returncode != 0 or data is None:
        msg = (clean_ps_error(decode_console(proc.stderr))
               or decode_console(proc.stdout).strip()
               or f"PowerShell exited with code {proc.returncode}")
        raise RuntimeError(msg)

    results = data.get("results") or []
    if isinstance(results, dict):
        results = [results]
    return data.get("mode") or "", results, data.get("cleanup") or ""


# --------------------------------------------------------------------------- #
# GUI helpers
# --------------------------------------------------------------------------- #
def show_text_window(parent, title: str, text: str):
    win = tk.Toplevel(parent)
    win.title(title)
    win.geometry("760x480")
    win.transient(parent)
    box = ScrolledText(win, wrap="none", font=("Consolas", 10))
    box.pack(fill="both", expand=True, padx=8, pady=8)
    box.insert("1.0", text)
    box.configure(state="disabled")
    bar = ttk.Frame(win)
    bar.pack(fill="x", padx=8, pady=(0, 8))

    def copy():
        win.clipboard_clear()
        win.clipboard_append(text)

    ttk.Button(bar, text="Copy to clipboard", command=copy).pack(side="left")
    ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")


class SettingsDialog(tk.Toplevel):
    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        s = app.settings
        self.title("Settings")
        self.transient(app)
        self.resizable(True, False)

        str_keys = ["author_name", "author_email", "cert_path", "key_path",
                    "script_dir", "timestamp_server", "hash_algorithm", "powershell_exe"]
        self.vars = {k: tk.StringVar(value=getattr(s, k)) for k in str_keys}

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)
        row = 0

        def section(title):
            nonlocal row
            ttk.Label(frm, text=title, font=("Segoe UI", 10, "bold")).grid(
                row=row, column=0, columnspan=3, sticky="w", pady=(12 if row else 0, 4))
            row += 1

        def entry(label, key, browse=None):
            nonlocal row
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
            ttk.Entry(frm, textvariable=self.vars[key], width=60).grid(
                row=row, column=1, sticky="ew", pady=2)
            if browse:
                ttk.Button(frm, text="Browse…", command=browse).grid(
                    row=row, column=2, padx=(6, 0), pady=2)
            row += 1

        def combo(label, key, values, readonly=False):
            nonlocal row
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
            ttk.Combobox(frm, textvariable=self.vars[key], values=values,
                         state="readonly" if readonly else "normal").grid(
                row=row, column=1, sticky="ew", pady=2)
            row += 1

        section("Signing Header")
        entry("Name:", "author_name")
        entry("Email:", "author_email")

        section("Paths")
        entry("Certificate:", "cert_path", self._browse_cert)
        entry("Private key:", "key_path", self._browse_key)
        entry("Script folder:", "script_dir", self._browse_dir)

        section("Signature")
        combo("Timestamp server:", "timestamp_server", TS_SERVERS)
        combo("Hash algorithm:", "hash_algorithm", ["SHA256", "SHA384", "SHA512"], True)
        combo("PowerShell:", "powershell_exe", ["powershell.exe", "pwsh.exe"])

        bar = ttk.Frame(frm)
        bar.grid(row=row, column=0, columnspan=3, sticky="e", pady=(14, 0))
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(bar, text="Save", command=self._save).pack(side="right", padx=6)

        self.grab_set()
        self.focus_set()

    def _initial(self, key):
        value = self.vars[key].get()
        return str(Path(value).parent) if value else self.vars["script_dir"].get() or None

    def _browse_cert(self):
        p = filedialog.askopenfilename(parent=self, title="Select certificate",
                                       filetypes=CERT_TYPES, initialdir=self._initial("cert_path"))
        if p:
            self.vars["cert_path"].set(p)

    def _browse_key(self):
        p = filedialog.askopenfilename(parent=self, title="Select private key",
                                       filetypes=KEY_TYPES, initialdir=self._initial("key_path"))
        if p:
            self.vars["key_path"].set(p)

    def _browse_dir(self):
        p = filedialog.askdirectory(parent=self, title="Select script folder",
                                    initialdir=self.vars["script_dir"].get() or None)
        if p:
            self.vars["script_dir"].set(p)

    def _save(self):
        s = self.app.settings
        for key, var in self.vars.items():
            value = var.get()
            setattr(s, key, value.strip() if isinstance(value, str) else value)
        try:
            s.save()
        except OSError as exc:
            messagebox.showerror("Error", f"Settings not saved:\n{exc}", parent=self)
            return
        self.app.apply_settings()
        self.app.log(f"Settings saved: {CONFIG_FILE}")
        self.destroy()


# --------------------------------------------------------------------------- #
# Main window
# --------------------------------------------------------------------------- #
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION} – Sign PowerShell Scripts")
        self.geometry("920x680")
        self.minsize(760, 540)

        self.settings = Settings.load()
        self.cert_var = tk.StringVar()
        self.key_var = tk.StringVar()
        self.pw_var = tk.StringVar()
        self.header_var = tk.BooleanVar(value=True)     # always on at startup
        self.backup_var = tk.BooleanVar(value=True)     # always on at startup
        self.status_var = tk.StringVar(value="Ready")
        self._busy_widgets = []

        self._build_menu()
        self._build_ui()
        self.apply_settings()
        for f in self.settings.script_files:
            if Path(f).is_file():
                self.listbox.insert("end", f)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- Layout ----------
    def _build_menu(self):
        menubar = tk.Menu(self)
        m_file = tk.Menu(menubar, tearoff=False)
        m_file.add_command(label="Settings…", command=self.open_settings)
        m_file.add_separator()
        m_file.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=m_file)
        m_help = tk.Menu(menubar, tearoff=False)
        m_help.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=m_help)
        self.config(menu=menubar)

    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}
        main = ttk.Frame(self, padding=8)
        main.pack(fill="both", expand=True)

        # Certificate & key
        cf = ttk.LabelFrame(main, text="Certificate & Key", padding=8)
        cf.pack(fill="x")
        cf.columnconfigure(1, weight=1)
        ttk.Label(cf, text="Certificate:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(cf, textvariable=self.cert_var).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(cf, text="Browse…", command=self.browse_cert).grid(row=0, column=2, **pad)
        ttk.Button(cf, text="Certificate Info", command=self.show_cert_info).grid(row=0, column=3, **pad)

        ttk.Label(cf, text="Private key:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(cf, textvariable=self.key_var).grid(row=1, column=1, sticky="ew", **pad)
        ttk.Button(cf, text="Browse…", command=self.browse_key).grid(row=1, column=2, **pad)
        ttk.Button(cf, text="Key Info", command=self.show_key_info).grid(row=1, column=3, **pad)

        ttk.Label(cf, text="Password:").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(cf, textvariable=self.pw_var, show="•").grid(row=2, column=1, sticky="ew", **pad)
        ttk.Label(cf, text="For PFX or encrypted key. Never stored.",
                  foreground="gray").grid(row=3, column=1, columnspan=3, sticky="w", padx=6)
        ttk.Label(cf, text="Leave the key field empty when using PFX/P12.",
                  foreground="gray").grid(row=4, column=1, columnspan=3, sticky="w", padx=6)

        # Scripts
        sf = ttk.LabelFrame(main, text="Scripts", padding=8)
        sf.pack(fill="both", expand=True, pady=(8, 0))
        sf.columnconfigure(0, weight=1)
        sf.rowconfigure(0, weight=1)
        lbf = ttk.Frame(sf)
        lbf.grid(row=0, column=0, sticky="nsew")
        self.listbox = tk.Listbox(lbf, selectmode="extended", activestyle="none")
        sb = ttk.Scrollbar(lbf, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=sb.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.listbox.bind("<Double-1>", lambda _e: self.verify())

        btns = ttk.Frame(sf)
        btns.grid(row=0, column=1, sticky="ns", padx=(8, 0))
        for text, cmd in [("Add files…", self.add_files),
                          ("Add folder…", self.add_folder),
                          ("Remove selected", self.remove_selected),
                          ("Clear list", lambda: self.listbox.delete(0, "end"))]:
            ttk.Button(btns, text=text, command=cmd).pack(fill="x", pady=2)
        ttk.Separator(btns).pack(fill="x", pady=6)
        vb = ttk.Button(btns, text="Verify signature", command=self.verify)
        vb.pack(fill="x", pady=2)
        self._busy_widgets.append(vb)

        # Action
        af = ttk.Frame(main)
        af.pack(fill="x", pady=8)
        ttk.Checkbutton(af, text="Insert signing header into script",
                        variable=self.header_var).pack(side="left")
        ttk.Checkbutton(af, text="Create backup before changes (.bak)",
                        variable=self.backup_var).pack(side="left", padx=(16, 0))
        # Highlighted main button (tk.Button, since ttk does not allow colors on Windows)
        sign_btn = tk.Button(af, text="🔏  Sign scripts", command=self.sign,
                             font=("Segoe UI", 11, "bold"), fg="white", bg="#0063B1",
                             activeforeground="white", activebackground="#004E8C",
                             disabledforeground="#D0D0D0", relief="flat", bd=0,
                             padx=18, pady=6, cursor="hand2")
        sign_btn.bind("<Enter>", lambda _e: sign_btn["state"] == "normal"
                      and sign_btn.configure(bg="#004E8C"))
        sign_btn.bind("<Leave>", lambda _e: sign_btn.configure(bg="#0063B1"))
        sign_btn.pack(side="right")
        self._busy_widgets.append(sign_btn)

        # Log
        lf = ttk.LabelFrame(main, text="Log", padding=4)
        lf.pack(fill="both", expand=True)
        self.log_box = ScrolledText(lf, height=10, font=("Consolas", 9), state="disabled")
        self.log_box.pack(fill="both", expand=True)

        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w",
                  padding=(6, 2)).pack(fill="x", side="bottom")

    # ---------- Settings ----------
    def apply_settings(self):
        s = self.settings
        self.cert_var.set(s.cert_path)
        self.key_var.set(s.key_path)

    def sync_to_settings(self):
        s = self.settings
        s.cert_path = self.cert_var.get().strip()
        s.key_path = self.key_var.get().strip()
        s.script_files = list(self.listbox.get(0, "end"))

    def open_settings(self):
        self.sync_to_settings()
        SettingsDialog(self)

    def on_close(self):
        if self._busy_widgets and str(self._busy_widgets[0]["state"]) == "disabled":
            if not messagebox.askyesno(APP_NAME, "An operation is still running. Exit anyway?"):
                return
        self.sync_to_settings()
        try:
            self.settings.save()
        except OSError:
            pass
        self.destroy()

    def show_about(self):
        messagebox.showinfo("About", f"{APP_NAME} {APP_VERSION}\n"
                            f"Author: {APP_AUTHOR}\n\n"
                            "A small Windows Python Application with GUI for signing PowerShell Scripts.\n\n"
                            f"Settings: {CONFIG_FILE}")

    # ---------- Log / status ----------
    def log(self, msg: str):
        stamp = dt.datetime.now().strftime("%H:%M:%S")
        self.after(0, self._append_log, f"[{stamp}] {msg}\n")

    def _append_log(self, line: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_busy(self, busy: bool, text: str = "Ready"):
        for w in self._busy_widgets:
            w.configure(state="disabled" if busy else "normal")
        self.status_var.set(text)
        self.configure(cursor="watch" if busy else "")

    # ---------- File selection ----------
    def _initial_dir(self, path: str):
        if path and Path(path).parent.is_dir():
            return str(Path(path).parent)
        return self.settings.script_dir or None

    def browse_cert(self):
        p = filedialog.askopenfilename(title="Select certificate", filetypes=CERT_TYPES,
                                       initialdir=self._initial_dir(self.cert_var.get()))
        if p:
            self.cert_var.set(p)
            if is_pfx(p):
                self.key_var.set("")

    def browse_key(self):
        p = filedialog.askopenfilename(title="Select private key", filetypes=KEY_TYPES,
                                       initialdir=self._initial_dir(self.key_var.get()))
        if p:
            self.key_var.set(p)

    def _add_paths(self, paths):
        existing = set(self.listbox.get(0, "end"))
        added = 0
        for p in paths:
            p = str(Path(p))
            if p not in existing:
                self.listbox.insert("end", p)
                existing.add(p)
                added += 1
        self.log(f"{added} file(s) added.")

    def add_files(self):
        paths = filedialog.askopenfilenames(title="Select scripts", filetypes=SCRIPT_TYPES,
                                            initialdir=self.settings.script_dir or None)
        if paths:
            self.settings.script_dir = str(Path(paths[0]).parent)
            self._add_paths(paths)

    def add_folder(self):
        folder = filedialog.askdirectory(title="Select folder",
                                         initialdir=self.settings.script_dir or None)
        if not folder:
            return
        self.settings.script_dir = folder
        recursive = messagebox.askyesno("Add folder", "Include subfolders?")
        pattern = "**/*" if recursive else "*"
        files = sorted(str(p) for p in Path(folder).glob(pattern)
                       if p.is_file() and p.suffix.lower() in SCRIPT_EXT)
        if not files:
            messagebox.showinfo("Add folder", "No PowerShell files found.")
            return
        self._add_paths(files)

    def remove_selected(self):
        for idx in reversed(self.listbox.curselection()):
            self.listbox.delete(idx)

    # ---------- Info windows ----------
    def show_cert_info(self):
        path = self.cert_var.get().strip()
        if not path:
            messagebox.showwarning(APP_NAME, "Please select a certificate first.")
            return
        try:
            cert, key, chain = load_material(path, "", self.pw_var.get())
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not load certificate:\n{exc}\n\n"
                                 "For PFX files, enter the password if required.")
            return
        text = cert_info_text(cert, chain)
        if is_pfx(path):
            text += f"\n\nPrivate key in PFX: {'yes' if key else 'no'}"
        show_text_window(self, f"Certificate – {Path(path).name}", text)

    def show_key_info(self):
        kpath, cpath, pw = self.key_var.get().strip(), self.cert_var.get().strip(), self.pw_var.get()
        cert = None
        try:
            if kpath:
                key = load_private_key(kpath, pw)
            elif cpath and is_pfx(cpath):
                cert, key, _ = load_material(cpath, "", pw)
                if key is None:
                    raise ValueError("The PFX file does not contain a private key.")
            else:
                messagebox.showwarning(APP_NAME, "Please select a private key first.")
                return
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not load key:\n{exc}")
            return
        if cert is None and cpath:
            try:
                cert, _, _ = load_material(cpath, "", pw)
            except Exception:
                cert = None
        title = Path(kpath or cpath).name
        show_text_window(self, f"Private key – {title}", key_info_text(key, cert))

    # ---------- Verify ----------
    def _selected_or_all(self):
        sel = self.listbox.curselection()
        return [self.listbox.get(i) for i in sel] if sel else list(self.listbox.get(0, "end"))

    def verify(self):
        files = self._selected_or_all()
        if not files:
            messagebox.showinfo(APP_NAME, "No scripts in the list.")
            return
        self._set_busy(True, f"Verifying {len(files)} file(s) …")
        threading.Thread(target=self._verify_worker, args=(files,), daemon=True).start()

    def _verify_worker(self, files):
        try:
            mode, results, _ = run_powershell(self.settings, PS_VERIFY, files)
            self._log_mode(mode)
            for r in results:
                self.log(f"{r.get('status', '?'):<14} {r.get('path')}")
                if r.get("signer"):
                    self.log(f"{'':14} Signed by:   {r['signer']} (valid until {r.get('valid_until')})")
                    self.log(f"{'':14} Thumbprint:  {r.get('thumbprint')}")
                    self.log(f"{'':14} Timestamp:   {r.get('timestamper') or 'NONE'}")
                if r.get("status") != "Valid" and r.get("message"):
                    self.log(f"{'':14} {r['message']}")
        except Exception as exc:
            self.log(f"ERROR during verification: {exc}")
        finally:
            self.after(0, self._set_busy, False)

    # ---------- Sign ----------
    def sign(self):
        files = list(self.listbox.get(0, "end"))
        if not files:
            messagebox.showinfo(APP_NAME, "Please add scripts first.")
            return
        cpath = self.cert_var.get().strip()
        if not cpath:
            messagebox.showwarning(APP_NAME, "Please select a certificate.")
            return
        try:
            cert, key, chain = load_material(cpath, self.key_var.get().strip(), self.pw_var.get())
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not load certificate/key:\n{exc}")
            return

        if key is None:
            messagebox.showerror(APP_NAME, "No private key available.")
            return
        if not key_matches_cert(key, cert):
            messagebox.showerror(APP_NAME, "The private key does not match the certificate.")
            return
        if not has_code_signing_eku(cert):
            messagebox.showerror(APP_NAME, "The certificate is not valid for code signing "
                                 "(extended key usage missing).")
            return
        valid, status = cert_validity(cert)
        if not valid:
            messagebox.showerror(APP_NAME, f"The certificate is {status}.")
            return
        if not self.settings.timestamp_server and not messagebox.askyesno(
                APP_NAME, "No timestamp server configured.\n\nWithout a timestamp, signatures "
                "become invalid once the certificate expires. Continue anyway?"):
            return

        insert_header = bool(self.header_var.get())
        backup = bool(self.backup_var.get())
        if not messagebox.askyesno(
                "Sign",
                f"Sign {len(files)} file(s)?\n\n"
                f"Certificate: {cert.subject.rfc4514_string()}\n{status}\n"
                f"Signing header: {'yes' if insert_header else 'no'}\n"
                f"Backup (.bak): {'yes' if backup else 'no'}"):
            return

        pfx_bytes, pfx_pw = build_pfx(cert, key)
        self._set_busy(True, f"Signing {len(files)} file(s) …")
        threading.Thread(target=self._sign_worker,
                         args=(files, cert, pfx_bytes, pfx_pw, insert_header, backup),
                         daemon=True).start()

    def _log_mode(self, mode: str):
        if mode and mode != "FullLanguage":
            self.log(f"PowerShell language mode: {mode} (probably AppLocker/WDAC) – "
                     "compatibility mode active.")

    def _sign_worker(self, files, cert, pfx_bytes, pfx_pw, insert_header, backup):
        s = self.settings
        try:
            ready = []
            for f in files:
                try:
                    if backup:
                        shutil.copy2(f, f + ".bak")
                    if insert_header and Path(f).suffix.lower() in HEADER_EXT:
                        note = apply_header(f, s, cert)
                        self.log(f"Signing header inserted: {f}" + (f" ({note})" if note else ""))
                    else:
                        warn = encoding_warning(f)
                        if warn:
                            self.log(f"Note {Path(f).name}: {warn}")
                    ready.append(f)
                except Exception as exc:
                    self.log(f"ERROR preparing {f}: {exc}")
            if not ready:
                return

            self.log(f"Signing {len(ready)} file(s) with {s.hash_algorithm}"
                     f"{', timestamp: ' + s.timestamp_server if s.timestamp_server else ''} …")
            thumb = thumbprint(cert)
            mode, results, cleanup = run_powershell(
                s, PS_SIGN, ready,
                job_extra={"hash": s.hash_algorithm or "SHA256",
                           "timestamp": s.timestamp_server,
                           "thumbprint": thumb},
                secret_env={"PSSIGNER_PW": pfx_pw},
                pfx_bytes=pfx_bytes)
            self._log_mode(mode)
            if cleanup == "failed":
                self.log(f"WARNING: The temporarily imported certificate ({thumb}) could not be "
                         "removed from CurrentUser\\My. Please delete it manually in certmgr.msc.")

            ok = 0
            for r in results:
                status, path = r.get("status", "?"), r.get("path")
                if status == "Valid":
                    ok += 1
                    self.log(f"OK             {path}")
                else:
                    self.log(f"{status:<14} {path}")
                    if r.get("message"):
                        self.log(f"{'':14} {r['message']}")
                    if status == "UnknownError":
                        self.log(f"{'':14} Note: Often the file is signed, but the root "
                                 "certificate is not trusted on this machine.")
            self.log(f"Done: {ok} of {len(ready)} file(s) validly signed.")
        except Exception as exc:
            self.log(f"ERROR while signing: {exc}")
        finally:
            self.after(0, self._set_busy, False)


def main():
    if os.name != "nt":
        print("Note: Signing only works on Windows.", file=sys.stderr)
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
