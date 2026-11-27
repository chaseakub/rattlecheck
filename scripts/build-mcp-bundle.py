"""Wrap a dependency-free RattleCheck npm tarball for local stdio MCP clients."""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

SERVER_NAME = "io.github.chaseakub/rattlecheck-supabase-migration-review"
DESCRIPTION = "Review local Supabase SQL migrations for PostgreSQL row-level security (RLS) and column grants."
REPOSITORY = "https://github.com/chaseakub/rattlecheck"


def json_bytes(data):
    return (json.dumps(data, indent=2) + "\n").encode()


def write_entry(archive, name, data):
    # Keep hashes stable across machines and retries, including the ZIP timestamp and file mode.
    info = ZipInfo(name)
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def build(tarball, output):
    output.mkdir(parents=True, exist_ok=True)
    bundle = output / "rattlecheck.mcpb"
    with tarfile.open(tarball, "r:gz") as npm:
        package = json.load(npm.extractfile("package/package.json"))
        version = package["version"]
        if package["name"] != "rattlecheck" or not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("Expected a stable RattleCheck package")
        if package.get("dependencies") or package.get("optionalDependencies") or package.get("peerDependencies"):
            raise ValueError("Bundle the runtime dependencies before distributing this version")

        entry = package["bin"]["rattlecheck"]
        npm.getmember("package/" + entry)
        manifest = {
            "manifest_version": "0.3",
            "name": "rattlecheck",
            "display_name": "RattleCheck for Supabase migrations",
            "version": version,
            "description": DESCRIPTION,
            "author": {"name": "RattleCheck", "url": REPOSITORY},
            "repository": {"type": "git", "url": REPOSITORY},
            "homepage": REPOSITORY,
            "license": package["license"],
            "compatibility": {"runtimes": {"node": package["engines"]["node"]}},
            "server": {"type": "node", "entry_point": entry,
                       "mcp_config": {"command": "node", "args": ["${__dirname}/" + entry, "mcp"]}},
        }
        with ZipFile(bundle, "w") as archive:
            write_entry(archive, "manifest.json", json_bytes(manifest))
            for item in sorted(npm.getmembers(), key=lambda member: member.name):
                if item.isdir():
                    continue
                parts = item.name.split("/")
                if not item.isfile() or parts[0] != "package" or any(
                    part in ("", ".", "..") or "\\" in part for part in parts
                ) or len(parts) < 2 or parts[1] == "manifest.json":
                    raise ValueError(f"Unexpected npm archive entry: {item.name}")
                write_entry(archive, "/".join(parts[1:]), npm.extractfile(item).read())

    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    server = {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": SERVER_NAME, "title": manifest["display_name"], "description": DESCRIPTION,
        "version": version, "repository": {"url": REPOSITORY, "source": "github"},
        "websiteUrl": REPOSITORY,
        "packages": [{"registryType": "mcpb", "version": version, "transport": {"type": "stdio"},
                      "identifier": f"{REPOSITORY}/releases/download/v{version}/{bundle.name}",
                      "fileSha256": digest}],
    }
    (output / "server.json").write_bytes(json_bytes(server))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tarball", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.tarball, args.output)
