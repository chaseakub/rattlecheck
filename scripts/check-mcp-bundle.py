"""Start the packaged server as an MCP client would and review an owned SQL fixture."""
import json
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

bundle = Path(sys.argv[1])
fixture = Path(__file__).resolve().parents[1] / "examples/public-directory/001_directory.sql"
with TemporaryDirectory() as tmp:
    root = Path(tmp)
    with ZipFile(bundle) as archive:
        archive.extractall(root / "extension")
    manifest = json.loads((root / "extension/manifest.json").read_text())
    config = manifest["server"]["mcp_config"]
    command = [config["command"]] + [a.replace("${__dirname}", str(root / "extension")) for a in config["args"]]
    migrations = root / "example/supabase/migrations"
    migrations.mkdir(parents=True)
    shutil.copy(fixture, migrations)
    requests = [
        {"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25",
         "capabilities": {}, "clientInfo": {"name": "bundle-check", "version": "1"}}},
        {"method": "notifications/initialized"},
        {"id": 2, "method": "tools/list"},
        {"id": 3, "method": "tools/call", "params": {"name": "scan", "arguments": {"path": str(root / "example")}}},
    ]
    messages = "".join(json.dumps({"jsonrpc": "2.0", **req}) + "\n" for req in requests)
    process = subprocess.run(command, cwd=root, input=messages, text=True, capture_output=True,
                             check=True, timeout=20)
    replies = {reply["id"]: reply["result"] for reply in map(json.loads, process.stdout.splitlines())}
    assert replies[1]["serverInfo"]["version"] == manifest["version"]
    assert {"scan", "list_rules", "explain_rule"} <= {t["name"] for t in replies[2]["tools"]}
    report = replies[3]["structuredContent"]
    assert report["coverage"]["tablesSeen"] == 1 and any(
        f["rule"] == "RC006" and f["detail"] == "private_email" for f in report["findings"]
    )
    print("Packaged MCP server", manifest["version"], "advertised its tools and flagged the demo's private_email column.")
