"""Package already-built binaries and public deployment files, never local state."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import zipfile
import argparse
import platform as host_platform

root = Path(__file__).resolve().parents[1]
source = root / "telemetry-agent"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--platform', choices=['native', 'linux', 'windows', 'all'], default='native')
parser.add_argument('--output', type=Path, default=None)
args = parser.parse_args()
selected = ('windows' if os.name == 'nt' else 'linux') if args.platform == 'native' else args.platform
if args.platform == 'native' and host_platform.machine().lower() not in ['x86_64', 'amd64']:
    raise SystemExit('This release package template is x86_64 only; do not relabel another architecture')
release = args.output.resolve() if args.output else root / 'release' / 'telemetry-0.1.0'
release.mkdir(parents=True, exist_ok=True)
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--manifest-path", str(source / "Cargo.toml"), "--locked", "--format-version=1"], text=True))
packages = sorted(metadata["packages"], key=lambda p: (p["name"], p["version"]))
binaries = ["infrascope-agent", "infrascope-docker-collector", "infrascope-pve-collector"]
artifacts = []
for platform, directory, suffix in [
    ("linux-x86_64-gnu", source / "target/release", ""),
    ("windows-x86_64", source / "target/x86_64-pc-windows-gnu/release", ".exe"),
]:
    if selected != 'all' and (('windows' if suffix else 'linux') != selected):
        continue
    missing = [str(directory / (binary + suffix)) for binary in binaries if not (directory / (binary + suffix)).is_file()]
    if missing:
        raise SystemExit('Build the requested target first; missing: ' + ', '.join(missing))
    out = release / ("infrascope-telemetry-0.1.0-" + platform)
    if out.exists():
        raise SystemExit(f"Refusing to overwrite an existing release: {out}")
    out.mkdir()
    for binary in binaries:
        shutil.copy2(directory / (binary + suffix), out / (binary + suffix))
    for folder in ["deploy", "examples", "docs"]:
        shutil.copytree(source / folder, out / folder)
    shutil.copy2(source / "README.md", out / "README.md")
    shutil.copy2(source / "Cargo.lock", out / "Cargo.lock")
    shutil.copy2(root / "docs/remote-access/TELEMETRY.md", out / "docs/PROTOCOL.md")
    licenses = out / "licenses"
    licenses.mkdir()
    inventory = []
    for package in packages:
        if package["name"] == "infrascope-telemetry":
            continue
        pdir = Path(package["manifest_path"]).parent
        files = []
        for candidate in sorted(pdir.iterdir()):
            if candidate.is_file() and candidate.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")):
                destination = licenses / (package["name"] + "-" + package["version"])
                destination.mkdir(exist_ok=True)
                shutil.copy2(candidate, destination / candidate.name)
                files.append(str((destination / candidate.name).relative_to(out)))
        inventory.append({k: package.get(k) for k in ["name", "version", "license", "repository", "source"]} | {"licenseFiles": files})
    (out / "DEPENDENCIES.json").write_text(json.dumps(inventory, indent=2) + "\n")
    (out / "BUILD.json").write_text(json.dumps({
        "version": "0.1.0", "platform": platform,
        "compiler": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "cargoLockSha256": hashlib.sha256((source / "Cargo.lock").read_bytes()).hexdigest(),
        "linuxRequirements": "x86_64 GNU, libgcc_s.so.1; validate libc compatibility for this build",
        "buildLibc": host_platform.libc_ver(),
        "windowsRequirements": "x86_64 Windows; native current-user DPAPI; unsigned binaries",
        "pveLiveVerification": "NOT_RUN", "serviceRebootVerification": "NOT_RUN",
        "dependencyInventoryScope": "Cargo.lock resolved packages includes test and other-target dependencies; not a security audit",
    }, indent=2) + "\n")
    files = sorted(p for p in out.rglob("*") if p.is_file())
    (out / "SHA256SUMS.txt").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.relative_to(out).as_posix() + "\n" for p in files))
    if suffix:
        archive = release / (out.name + ".zip")
        with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=6, strict_timestamps=False) as z:
            for p in sorted(out.rglob("*")):
                if p.is_file():
                    z.write(p, p.relative_to(release))
    else:
        archive = release / (out.name + ".tar.gz")
        with tarfile.open(archive, "x:gz") as t:
            t.add(out, arcname=out.name)
    artifacts.append({"file": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "bytes": archive.stat().st_size})
(release / "SHA256SUMS.txt").write_text("".join(a["sha256"] + "  " + a["file"] + "\n" for a in artifacts))
print(json.dumps({"release": str(release), "artifacts": artifacts}, indent=2))
