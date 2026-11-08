#!/usr/bin/env python3
"""Verify a published server and setup utility using an isolated user profile."""
import argparse
from collections import deque
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--version", default="1.0.0")
    args = parser.parse_args()
    suffix = ".exe" if os.name == "nt" else ""
    server = (args.payload / "server" / ("AgentShark.Server" + suffix)).resolve()
    setup = (args.payload / "setup" / ("AgentShark.Setup" + suffix)).resolve()
    with tempfile.TemporaryDirectory(prefix="agent-shark-release-") as temporary:
        home = Path(temporary) / "home"
        home.mkdir()
        def configure(command):
            return json.loads(subprocess.check_output([str(setup), command, "--clients", "all", "--home", str(home), "--server", str(server)], text=True, encoding="utf-8"))
        assert all(item["status"] == "registered" for item in configure("integrate"))
        assert all(item["status"] == "unchanged" for item in configure("integrate"))
        assert all(item["status"] == "removed" for item in configure("remove"))
        env = os.environ.copy()
        env["AGENTSHARK_DATA_DIRECTORY"] = str(Path(temporary) / "evidence")
        process = subprocess.Popen([str(server)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env)
        responses = queue.Queue()
        errors = deque(maxlen=50)
        def read_stdout():
            for line in process.stdout:
                try: responses.put(json.loads(line))
                except json.JSONDecodeError: responses.put({"error": "Non-JSON output on MCP stdout"})
        def read_stderr():
            for line in process.stderr: errors.append(line)
        threading.Thread(target=read_stdout, daemon=True).start()
        threading.Thread(target=read_stderr, daemon=True).start()
        def send(message):
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
        def call(identifier, method, params=None):
            send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}})
            while True:
                message = responses.get(timeout=30)
                if message.get("id") != identifier: continue
                assert "error" not in message, message
                return message["result"]
        try:
            init = call(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "release-verifier", "version": "1.0.0"}})
            assert init["serverInfo"]["version"] == args.version, init
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            assert len(call(2, "tools/list")["tools"]) == 11
            capabilities = call(3, "tools/call", {"name": "get_capabilities", "arguments": {}})
            assert not capabilities.get("isError", False), capabilities
            start = call(4, "tools/call", {"name": "start_observation", "arguments": {"request": {"mode": "proxy", "allowedHosts": ["localhost"], "durationSeconds": 10}}})
            assert not start.get("isError", False), start
            observation = start["structuredContent"]["observation"]["id"]
            stop = call(5, "tools/call", {"name": "stop_observation", "arguments": {"observationId": observation}})
            assert not stop.get("isError", False), stop
            process.stdin.close()
            assert process.wait(timeout=15) == 0
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=10)
        print("Release smoke checks passed: setup, idempotence, uninstall, MCP initialization, tools and observation lifecycle.")


if __name__ == "__main__":
    main()
