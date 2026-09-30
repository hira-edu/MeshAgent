# MeshAgent Release Checklist

## Build and verify

- [ ] Confirm the intended local branding and provisioning manifest are selected.
- [ ] Build the package with `msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`.
- [ ] Run focused contracts for the changed surfaces and the release bundle/signing gates.
- [ ] Verify the package's executables, service DLL, embedded bundle, and `.msh` files came from the same build.
- [ ] Validate signing against the active branding policy.
- [ ] Run the read-only server identity gate described in [Deployment](../DEPLOYMENT.md#agent-server-identity-check).

## Publish to the VPS

- [ ] Set `MESHCENTRAL_SERVER` and the active branding configuration for `deploy.py`.
- [ ] Run `python .\deploy.py status` and review the target before changing it.
- [ ] Run `python .\deploy.py stage`; review the staged file list and digest verification.
- [ ] Run `python .\deploy.py deploy` and confirm the target interactively.
- [ ] Run `python .\deploy.py health` and review the post-deployment state.
- [ ] Keep the generated release manifest under ignored `artifacts/deployment/`; do not commit runtime evidence.

See [Deployment](../DEPLOYMENT.md) for rollback and maintenance commands.
