# PS-Signer

A small Windows Python Application with GUI for signing PowerShell Scripts.

Certificate and private key are selected as files, certificate details can be displayed, and paths as well as signing header information are saved persistently.

## Requirements

- Windows 10/11 or Windows Server
- Windows PowerShell 5.1 (`powershell.exe`) or PowerShell 7 (`pwsh.exe`)
- Python 3.9 or later (tkinter is included in the official Windows installer)
- A certificate with the extended key usage **Code Signing**

## Installation

```powershell
python -m pip install -r requirements.txt
```

Optionally in a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

```powershell
python ps_signer.py
```

Without a console window: `pythonw ps_signer.py`

## Supported certificate formats

| Certificate | Private key | Note |
|---|---|---|
| `.pfx` / `.p12` | contained in the PFX | Leave the key field empty, enter the password |
| `.pem` / `.crt` / `.cer` | `.pem` / `.key` | Key may be encrypted (enter the password) |

Certificates in the Windows certificate store or on smart cards/tokens are currently not supported.

## How to use

1. Select the **certificate** and, if needed, the **private key**, and enter the password if required.
2. Use **Certificate Info** or **Key Info** to check the details: subject, issuer, validity, thumbprint, key type, code signing permission, and whether key and certificate match.
3. Add scripts via **Add files…** or **Add folder…** (`.ps1`, `.psm1`, `.psd1`, `.ps1xml`).
4. Choose the options next to the sign button: **Insert signing header into script** (enabled by default at every start) and **Create backup before changes (.bak)** (also enabled by default at every start).
5. Click **Sign scripts**. The result is shown in the log.
6. Use **Verify signature** (or double-click a file) to check the signature status. If nothing is selected, all files are verified.

## Settings

Under **File → Settings…** you can configure:

- Signing header: name, email
- Default paths: certificate, private key, script folder
- Timestamp server (default: `http://timestamp.digicert.com`)
- Hash algorithm (SHA256, SHA384, SHA512)
- PowerShell version (`powershell.exe` or `pwsh.exe`)

Settings are stored in `C:\Users\<username>\.ps-signer\settings.json`. When closing the application, the current paths and the script list are saved automatically. **Passwords are never stored.**

## Signing header

An Authenticode signature has no author field of its own; the signer is always the name in the certificate. If the option is enabled, a comment block is written to the top of the script before signing:

```powershell
# --- Signing Header ---
# Name:        John Doe
# Email:       john@example.com
# Signed on:   2026-09-28 14:03
# Certificate: CN=John Doe
# Thumbprint:  EF99BD83...
# --- End Signing Header ---
```

When re-signing, an existing header is replaced, not duplicated. This also applies to headers created by older versions. No header is inserted into `.ps1xml` files (XML).

## Important notes

**Timestamp:** Without a timestamp, signatures become invalid as soon as the certificate expires. An internet connection to the timestamp server is required.

**Self-signed certificates:** The script is signed, but is only trusted on other machines if the certificate has been imported there into *Trusted Root Certification Authorities* and *Trusted Publishers*. The status `UnknownError` after signing usually means exactly that.

**Encoding:** Windows PowerShell 5.1 misreads UTF-8 files without BOM that contain non-ASCII characters. PS-Signer warns you in this case and automatically saves as UTF-8 with BOM when inserting the header.

**Changes after signing:** Any change to the script invalidates the signature. The script must be signed again afterwards.

## Security

Certificate and private key are loaded and validated in Python and then combined into a temporary PFX file. It is encrypted with a random one-time password, exists only for the duration of the operation in the user's temp folder, and is deleted afterwards. The password is passed to the PowerShell process via an environment variable only.

- **PowerShell 7 (`pwsh.exe`):** The certificate is loaded directly from the PFX (`Get-PfxCertificate -Password`); the Windows certificate store is not touched.
- **Windows PowerShell 5.1 (`powershell.exe`):** `Get-PfxCertificate` has no password parameter here. The certificate is therefore temporarily imported into `CurrentUser\My` and removed together with its key after signing. If it was already present, the existing one is used and not deleted. If removal fails, a warning with the thumbprint appears in the log.

Private key files should nevertheless always be password-protected and never committed to version control.

## Constrained Language Mode (AppLocker/WDAC)

In corporate environments, PowerShell often runs in *Constrained Language Mode*. The PowerShell parts of PS-Signer therefore use cmdlets only and no direct .NET calls. If this mode is active, a note appears in the log. The current mode is shown by `$ExecutionContext.SessionState.LanguageMode`.

## Troubleshooting

| Problem | Solution |
|---|---|
| `The package 'cryptography' is missing` | Run `python -m pip install -r requirements.txt` |
| `No module named 'tkinter'` | Reinstall Python with the official installer from python.org and enable the option "tcl/tk and IDLE" |
| "Invalid password or PKCS12 data" | Check the PFX password |
| "The private key does not match the certificate" | Certificate and key do not belong together; compare *Public key SHA256* in the info windows |
| "not valid for code signing" | Use a certificate with the *Code Signing* usage |
| Status `HashMismatch` on verification | The file was modified after signing; sign it again |
| Status `NotSigned` | The file is not signed |
| "…already exists WITHOUT a private key in CurrentUser\My" | Delete the certificate in `certmgr.msc` under *Personal*, or use PowerShell 7 |
| Warning: temporarily imported certificate not removed | Delete it in `certmgr.msc` under *Personal* using the thumbprint |
| Timestamping fails | Check internet connection/proxy or choose a different timestamp server |

## Creating a test certificate (for testing only)

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Test Signer" `
        -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable
$pw = Read-Host -AsSecureString "PFX password"
Export-PfxCertificate -Cert $cert -FilePath .\test-signer.pfx -Password $pw
```

The resulting `test-signer.pfx` can be selected directly in PS-Signer.

## Files

- `ps_signer.py` – the application
- `requirements.txt` – Python dependencies
- `README.md` – this guide
