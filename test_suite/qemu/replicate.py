#!/usr/bin/env python3
"""Check initial sync and transaction-log replication between two microvms."""
import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('primary_release')
    parser.add_argument('secondary_release')
    parser.add_argument('--workdir', type=Path)
    parser.add_argument('--timeout', type=int, default=240)
    args = parser.parse_args()
    work = args.workdir or Path(tempfile.mkdtemp(prefix='mars-replication-'))
    if args.workdir:
        work.mkdir(parents=True, exist_ok=False)
    print(f'Artifacts: {work}', flush=True)
    for node, release in [('primary', args.primary_release), ('secondary', args.secondary_release)]:
        subprocess.run([sys.executable, str(HERE / 'run.py'), release, '--prepare-only',
                        '--workdir', str(work / node), '--guest-script', str(HERE / 'replication.sh'),
                        '--append', f'mars_test_node={node}'], check=True)
    # QEMU's socket transport forms a private Ethernet link; no TAP or root needed.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    processes = []
    logs = []
    try:
        for node in ('primary', 'secondary'):
            cmd = json.loads((work / node / 'command.json').read_text())
            idx = cmd.index('-netdev') + 1
            mode = 'listen' if node == 'primary' else 'connect'
            cmd[idx] = f'socket,id=net0,{mode}=127.0.0.1:{port}'
            idx = cmd.index('virtio-net-device,netdev=net0')
            cmd[idx] += ',mac=52:54:00:42:00:' + ('01' if node == 'primary' else '02')
            (work / node / 'command.json').write_text(json.dumps(cmd, indent=2))
            log = (work / node / 'console.log').open('w')
            logs.append(log)
            processes.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
            if node == 'primary':
                time.sleep(.5)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            text = [(work / n / 'console.log').read_text(errors='replace') for n in ('primary', 'secondary')]
            if any(re.search(r'BUG:|WARNING: CPU:|Oops:|Kernel panic|Initramfs unpacking failed|MARS_QEMU_FAIL', t) for t in text):
                raise RuntimeError(f'Guest failure; inspect {work}')
            if 'MARS_QEMU_PRIMARY_WRITTEN' in text[0] and 'MARS_QEMU_REPLICATION_PASS' in text[1]:
                print(f'PASS: {args.primary_release} -> {args.secondary_release}', flush=True)
                return
            if any(p.poll() is not None for p in processes):
                raise RuntimeError(f'Guest exited before completing replication; inspect {work}')
            time.sleep(1)
        raise RuntimeError(f'Replication timed out; inspect {work}')
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
