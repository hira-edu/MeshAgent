# MeshAgent documentation

MeshAgent runs on endpoints the operator owns or is authorized to administer.
These documents describe the current package, configuration, lifecycle, and
validation contracts.

- [Configuration](CONFIGURATION.md): branding, provisioning, runtime policy,
  service recovery, and update transport.
- [Deployment](DEPLOYMENT.md): package staging, publishing, backups, rollback,
  and Windows lifecycle operations.
- [Testing](testing/README.md): build prerequisites, source contracts, runtime
  probes, local lifecycle regression, and release gates.

The Windows service uses the system svchost executable with a dedicated group
containing only the configured agent service. Approved helper and compatibility
lifecycle operations use explicit rundll32 exports. Local identities and secrets
belong in ignored configuration files; generated validation evidence belongs in
`artifacts/validation/`.
