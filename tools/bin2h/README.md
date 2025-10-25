# bin2h

Command-line helper that converts arbitrary binaries (DLLs, payloads, provisioning blobs) into self-contained C/C++ headers. Each header packs the payload bytes, exposes size/SHA-256 helpers, and can optionally be wrapped inside namespaces or paired with a JSON manifest for build provenance.

## Usage
```powershell
bin2h --input meshservice\x64\StealthLab_DLL\MeshService-2022.dll `
      --output meshcore\embedded\svchost_payload.h `
      --symbol g_SvchostPayload `
      --metadata dist\svchost_payload.json `
      --metadata-only
```

### Supported switches
| Option | Description |
| --- | --- |
| `--input`, `-i` | Source binary. Required. |
| `--output`, `-o` | Destination header path. Required. |
| `--symbol`, `-s` | Array identifier (defaults to `g_BinaryBlob`). |
| `--guard`, `-g` | Custom include guard (auto-derived when omitted). |
| `--namespace` | Wrap definitions inside a `::`-delimited namespace path. |
| `--bytes-per-line` | Number of hex bytes per line (default 12, max 32). |
| `--metadata` | Optional JSON manifest describing size/SHA-256. |
| `--metadata-only` | Skip emitting the byte array; only size/hash helpers are generated. |
| `--help`, `-h` | Show usage and exit. |

The generated header always emits metadata helpers:

```c
static const uint8_t g_SvchostPayload[] = { /* ... */ };   // omitted when --metadata-only is used
static const size_t  g_SvchostPayload_SIZE   = sizeof(g_SvchostPayload); // or literal size with --metadata-only
static const char    g_SvchostPayload_SHA256[] = "fd34...c446";
```

When no namespace is requested, the tool also wraps the definitions in `extern "C"` guards so the header can be consumed from both C and C++ translation units.
