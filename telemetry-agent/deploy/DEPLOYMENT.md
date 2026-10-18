# Deployment and service boundaries

Use the `start-linux.sh` or `start-windows.ps1` foreground wrapper first. They
run the chosen packaged binary with an existing configuration, inherit secrets
only from the process environment, and return the binary's exit status. They
do not request elevation, enroll implicitly, or install services.

```sh
./deploy/start-linux.sh host /absolute/host.toml sample
./deploy/start-linux.sh host /absolute/host.toml enroll
./deploy/start-linux.sh host /absolute/host.toml run
```

```powershell
.\deploy\start-windows.ps1 -Kind host -Config C:\InfraScope\host.toml -Command sample
.\deploy\start-windows.ps1 -Kind host -Config C:\InfraScope\host.toml -Command enroll
.\deploy\start-windows.ps1 -Kind host -Config C:\InfraScope\host.toml -Command run
```

Before enrollment set the enrollment token in that process's environment using
your secret-management mechanism. The PVE collector additionally needs the
environment variable named by `pve.token_env`. Do not put real secrets in
examples, shell command lines, URLs, checked-in configuration, or chat.

## Linux systemd

`install-linux.sh` is optional and must be explicitly invoked with `sudo` and
`--install host|docker|pve`. It installs a dedicated account, one binary, a state
directory, and a disabled unit. It refuses existing binary/unit targets and
does not overwrite configurations, enable services, or start collection.

```sh
sudo ./deploy/install-linux.sh --install host
```

After reviewing the generated example, create `/etc/infrascope/host.toml` as
`root:infrascope-agent`, mode `0640`. Set an absolute state directory to
`/var/lib/infrascope-host`, and install the trusted server CA. Enroll with the
binary as `infrascope-agent`, not root, so that its state ownership is correct.
Use a secret manager or a private environment-preserving shell for the short
enrollment step; revoke unused enrollment tokens. Inspect `status`, then:

```sh
sudo systemctl enable --now infrascope-host.service
sudo systemctl status infrascope-host.service
sudo journalctl -u infrascope-host.service
```

Repeat separately for Docker/PVE and their distinct state directories. The
installer does not grant access to the Docker socket or add a user to the
Docker group. Grant the intended least-privilege read proxy/socket access
yourself after reviewing Docker's host-control implications. The PVE unit
expects a root-owned `/etc/infrascope/pve-token.env`, mode `0600`, containing
the configured environment variable. The token remains accessible to processes
running as the service user and to root; use a dedicated least-privilege token.

These unit files are templates, not proof of target-host service acceptance.
Host filesystem and network observations can be affected by service sandboxing,
namespaces, and permissions. Validate expected interfaces/mounts on the actual
target. The application performs only bounded operations, but up to 60 seconds
of collection plus 30 seconds of queued transmission may precede a clean stop;
unacknowledged queued samples remain on disk.

## Windows

Windows foreground operation does not require administrative privileges for
ordinary host metrics. The identity seed is protected using current-user
Windows DPAPI. Run later commands using the same Windows account that enrolled.
Use a private state directory whose ACL grants only that account and the
intended administrative/system principals. Never place state in a shared
directory or copy an enrollment identity to another computer/account.

The binaries implement `run-service` for Windows SCM, but this release does
not automatically install a Windows service. A service identity different from
the enrollment account cannot decrypt the DPAPI identity. A service can also
lack interactive-user environment variables, network access, and CA/file
permissions. Until enrollment under the exact intended service identity,
service logon rights, protected secret delivery, start/stop/restart, and metrics
upload have been verified, use the foreground wrapper and leave service
acceptance incomplete. Do not change the account to LocalSystem merely to
silence an access error. No UAC prompt is triggered by these deployment files.
