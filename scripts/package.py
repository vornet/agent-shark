#!/usr/bin/env python3
"""Build self-contained release payloads and native installers without third-party Python packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rid", required=True, choices=["win-x64", "win-arm64", "linux-x64", "linux-arm64", "osx-x64", "osx-arm64"])
    parser.add_argument("--version", required=True)
    parser.add_argument("--skip-publish", action="store_true")
    args = parser.parse_args()
    version = ET.parse(ROOT / "Directory.Build.props").findtext("PropertyGroup/Version")
    if args.version != version:
        raise SystemExit("Release version must match the reviewed Directory.Build.props version")
    output = ROOT / "artifacts" / "release"
    output.mkdir(parents=True, exist_ok=True)
    stage = ROOT / "artifacts" / "packaging" / args.rid
    payload = stage / "payload"
    payload.mkdir(parents=True, exist_ok=True)
    if not args.skip_publish:
        for name in ["Server", "Setup"]:
            run("dotnet", "publish", f"src/AgentShark.{name}", "-c", "Release", "-r", args.rid, "--self-contained", "true",
                "-p:RestoreLockedMode=false", "-p:AgentSharkPackaging=true", "-o", payload / name.lower())
    for name in ["README.md", "LICENSE", "THIRD-PARTY-NOTICES.md", "THIRD-PARTY-LICENSES.txt"]:
        shutil.copy2(ROOT / name, payload / name)
    stem = f"AgentShark-{version}-{args.rid}"
    if args.rid.startswith("win"):
        candidates = [p for root in [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")] if root for p in Path(root).glob("Inno Setup */ISCC.exe")]
        local_compiler = ROOT / "artifacts/build-tools/inno/ISCC.exe"
        if local_compiler.exists(): candidates.append(local_compiler)
        compiler = os.environ.get("ISCC") or shutil.which("iscc") or (str(sorted(candidates)[-1]) if candidates else "iscc")
        text = (ROOT / "packaging/windows.iss").read_text(encoding="utf-8")
        for key, value in {"VERSION": version, "PAYLOAD": payload, "OUTPUT": output, "RID": args.rid, "ARCH": "arm64" if args.rid == "win-arm64" else "x64compatible"}.items():
            text = text.replace(f"@{key}@", str(value))
        spec = stage / "installer.iss"
        spec.write_text(text, encoding="utf-8")
        run(compiler, spec)
    elif args.rid.startswith("osx"):
        shutil.copy2(ROOT / "packaging/uninstall.sh", payload / "uninstall.sh")
        os.chmod(payload / "uninstall.sh", 0o755)
        pkgroot = stage / "pkgroot" / "usr/local/lib/agent-shark"
        shutil.copytree(payload, pkgroot, dirs_exist_ok=True)
        scripts = stage / "pkg-scripts"
        scripts.mkdir(exist_ok=True)
        shutil.copy2(ROOT / "packaging/macos/postinstall", scripts / "postinstall")
        os.chmod(scripts / "postinstall", 0o755)
        run("pkgbuild", "--root", stage / "pkgroot", "--scripts", scripts, "--identifier", "com.vornet.agentshark", "--version", version, "--install-location", "/", output / f"{stem}.pkg")
    else:
        for name in ["install.sh", "uninstall.sh"]:
            shutil.copy2(ROOT / "packaging" / name, payload / name)
            os.chmod(payload / name, 0o755)
        debroot = stage / "debroot"
        shutil.copytree(payload, debroot / "opt/agent-shark", dirs_exist_ok=True)
        control = debroot / "DEBIAN"
        control.mkdir(exist_ok=True)
        arch = "amd64" if args.rid == "linux-x64" else "arm64"
        (control / "control").write_text(f"""Package: agent-shark
Version: {version}
Architecture: {arch}
Maintainer: AgentShark contributors <noreply@github.com>
Section: net
Priority: optional
Depends: libc6 (>= 2.35), libgcc-s1, libstdc++6, zlib1g, libssl3 | libssl3t64, libicu70 | libicu72 | libicu74 | libicu76 | libicu77 | libicu78, libpcap0.8 | libpcap0.8t64
Homepage: https://github.com/vornet/agent-shark
Description: Application network debugging for AI agents over MCP
 Self-contained headless server with local evidence and desktop client setup.
""", encoding="utf-8")
        for name in ["postinst", "prerm"]:
            shutil.copy2(ROOT / "packaging/linux" / name, control / name)
            os.chmod(control / name, 0o755)
        run("dpkg-deb", "--root-owner-group", "--build", debroot, output / f"{stem}.deb")
        with tarfile.open(output / f"{stem}.tar.gz", "w:gz") as archive:
            archive.add(payload, arcname=stem)
    # Native Claude Desktop bundle for the same platform, using the documented binary server format.
    bundle = stage / "mcpb"
    shutil.copytree(payload / "server", bundle / "server", dirs_exist_ok=True)
    binary = "AgentShark.Server.exe" if args.rid.startswith("win") else "AgentShark.Server"
    platform = "win32" if args.rid.startswith("win") else "darwin" if args.rid.startswith("osx") else "linux"
    manifest = {"manifest_version": "0.3", "name": "agent-shark", "display_name": "AgentShark", "version": version,
                "description": "Application network debugging for AI agents", "author": {"name": "AgentShark contributors"},
                "license": "MIT", "homepage": "https://github.com/vornet/agent-shark",
                "server": {"type": "binary", "entry_point": f"server/{binary}", "mcp_config": {"command": "${__dirname}/server/" + binary, "args": [],
                    "env": {"AGENTSHARK_DATA_DIRECTORY": "${user_config.data_directory}"}}},
                "compatibility": {"platforms": [platform]},
                "user_config": {"data_directory": {"type": "directory", "title": "Evidence directory", "description": "Private evidence directory unique to this Claude Desktop server instance", "default": "${HOME}/.agent-shark/claude-extension", "required": True}}}
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for name in ["LICENSE", "THIRD-PARTY-NOTICES.md", "THIRD-PARTY-LICENSES.txt"]:
        shutil.copy2(ROOT / name, bundle / name)
    with zipfile.ZipFile(output / f"{stem}.mcpb", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in bundle.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(bundle).as_posix())
    for artifact in sorted(output.glob(f"{stem}*")):
        if artifact.is_file() and artifact.suffix != ".sha256":
            digest = hashlib.file_digest(artifact.open("rb"), "sha256").hexdigest()
            (output / (artifact.name + ".sha256")).write_text(f"{digest}  {artifact.name}\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
