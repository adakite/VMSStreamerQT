# VMSStreamerQt

Qt C++ app for streaming and plotting Quaraze data from a plain FTP server (no FTPS).

## Build

### Makefile (recommended)
```bash
cd VMSStreamerQt
make build
make open   # macOS
```

### CMake
```bash
cd VMSStreamerQt
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt
cmake --build build
```

## Run
```bash
open build/VMSstreamerQt.app
```

## Release (GitHub Actions)
Tag a version to produce macOS/Windows/Linux release assets:
```bash
git tag v0.1.0
git push origin v0.1.0
```

Artifacts produced:
- macOS: `.dmg`
- Windows: `.msi`
- Linux: `.AppImage`

## Dependencies
- Qt 6 (Widgets, Charts)
- libcurl
- OpenSSL (Crypto) for Fernet decrypt

## Credentials
The app expects `credentials.json` and (if encrypted) `key.key` **next to the .app** (or the executable).

Plaintext example:
```json
{
  "ftp_host": "ftp.example.com",
  "ftp_user": "username",
  "ftp_pass": "password"
}
```

Encrypted credentials are supported (Fernet). If values start with `gAAAA...`, the app will load `key.key` and decrypt.

## Notes
- FTP only (plain). If `ftp_host` uses `ftps://` the app will show an error.
- CSV preview shows the first 100 rows.
- Plot uses `TIMESTAMP` column if available.
- Save plot to PNG/PDF.
