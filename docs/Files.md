# Repository Layout

This is the maintained path map for the MeshAgent fork.

## Root build and operations files

| Path | Purpose |
|---|---|
| `MeshAgent.Build.proj` | Ordered Windows package build |
| `MeshAgent-2022.sln` | Visual Studio solution used by current Windows projects |
| `makefile` | Upstream POSIX and cross-platform build matrix |
| `branding_config.json` | Checked-in fallback branding configuration |
| `branding_config.template.json` | Template for ignored local branding |
| `WinDiagnosticHost.msh` | Preferred provisioning manifest for this fork |
| `deploy.py` | MeshCentral artifact staging, deployment, rollback, and health CLI |
| `.env.template` | Deployment environment-variable template |
| `playwright.config.js` | UMH operator fixture test configuration |

## Source directories

| Directory | Contents |
|---|---|
| `meshcore/` | Agent control channel, identity, updates, signing, and KVM |
| `meshcore/KVM/Windows/` | Windows capture, input, session, and bridge implementation |
| `meshservice/` | Windows service executable/DLL projects and lifecycle modules |
| `meshconsole/` | Console-hosted agent project |
| `meshreset/` | Windows reset utility |
| `microstack/` | Event loop, socket, HTTP, WebRTC, process, crypto, and data-store primitives |
| `microscript/` | Duktape engine, script container, and native JS bindings |
| `modules/` | JavaScript modules loaded by the agent runtime |
| `snippets/` | Small embedded/runtime source fragments |
| `schema/` | Branding JSON schema |

Selected Microstack API notes remain under `docs/files/`:

- [ILibAsyncSocket](files/ILibAsyncSocket.md)
- [ILibAsyncUDPSocket](files/ILibAsyncUDPSocket.md)
- [ILibAsyncServerSocket](files/ILibAsyncServerSocket.md)
- [ILibCrypto](files/ILibCrypto.md)
- [ILibIPAddressMonitor](files/ILibIPAddressMonitor.md)
- [ILibMulticastSocket](files/ILibMulticastSocket.md)
- [ILibParsers](files/ILibParsers.md)

## Tests and tooling

| Directory | Contents |
|---|---|
| `test/` | Node contracts, native/runtime probes, grouped regression, C# GUI harness, and Playwright tests |
| `test/lib/` | Shared test helpers and contract models |
| `tools/` | Branding generators, signing checks, runtime validation, publication helpers, and health checks |
| `verification/` | Small tracked validation fixtures |
| `.github/workflows/` | Active build/release and CodeQL workflows |

## Dependencies

| Directory | Contents |
|---|---|
| `openssl/` | OpenSSL headers and prebuilt platform libraries used by the build |
| `lib-jpeg-turbo/` | JPEG acceleration inputs for KVM builds |
| `webrtc/` | WebRTC sources and sample bindings |

## Generated and local-only paths

The following are ignored and must not be treated as source:

- `artifacts/`, `build/`, `dist/`, `out/`
- top-level and project `x64/`, `Win32/`, `Release/`, and intermediate folders
- `meshservice/embedded/svchost_payload.dll`
- `meshcore/generated/` build outputs
- `branding_config.local.json`, `.env`, logs, dumps, traces, and archives

Use [Configuration](CONFIGURATION.md), [Testing](testing/README.md), and
[Deployment](DEPLOYMENT.md) for the workflows that create or consume these
paths.
