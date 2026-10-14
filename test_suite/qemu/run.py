#!/usr/bin/env python3
"""Build MARS and boot an installed x86-64 kernel in an isolated QEMU microvm."""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', help='installed kernel release, as in /lib/modules')
    parser.add_argument('--workdir', type=Path, help='new directory for images and logs')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--guest-script', type=Path, default=REPO / 'test_suite/qemu/guest.sh')
    parser.add_argument('--append', default='', help='additional guest kernel arguments')
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--accel', choices=('kvm', 'tcg'), default='kvm')
    args = parser.parse_args()
    modules = Path('/lib/modules') / args.release
    kdir = modules / 'build'
    work = args.workdir or Path(tempfile.mkdtemp(prefix='mars-qemu-'))
    if args.workdir:
        work.mkdir(parents=True, exist_ok=False)
    work = work.resolve()
    print(f'Artifacts: {work}', flush=True)
    source = work / 'source'
    source.mkdir()
    shutil.copytree(REPO / 'kernel', source / 'kernel', ignore=shutil.ignore_patterns(
        '*.o', '*.ko', '*.cmd', '*.mod', '*.mod.c', 'Module.symvers',
        'modules.order', 'buildtag.h', 'mars_config.h'))
    shutil.copytree(REPO / 'scripts', source / 'scripts')
    config = (kdir / '.config').read_text()
    make = ['make', '-C', source / 'kernel', f'KDIR={kdir}', '-j8']
    if 'CONFIG_CC_IS_CLANG=y' in config:
        make.append('LLVM=1')
    with (work / 'build.log').open('w') as log:
        run(make, stdout=log, stderr=subprocess.STDOUT)
    root = work / 'root'
    root.mkdir()
    for directory in ('dev', 'proc', 'sys', 'run', 'tmp', 'etc', 'mars', 'mnt', 'usr/bin', 'usr/lib'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for link, target in [('bin', 'usr/bin'), ('sbin', 'usr/bin'), ('lib', 'usr/lib'),
                         ('lib64', 'usr/lib'), ('usr/sbin', 'bin')]:
        (root / link).symlink_to(target)
    copied = set()

    def copy_file(path):
        path = Path(path)
        dest = root / path.relative_to('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            dest.unlink()
        shutil.copy2(path, dest, follow_symlinks=True)

    def copy_binary(path):
        path = Path(path)
        if path in copied:
            return
        copied.add(path)
        copy_file(path)
        result = subprocess.run(['ldd', str(path)], text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        for lib in re.findall(r'(?:=>\s+)?(/[^\s]+)', result.stdout):
            copy_file(lib)

    binaries = ('bash sh mount umount mountpoint hostname uname cat chmod mkdir ln readlink sleep '
                'touch stat dd cmp sync rm mv cp dirname basename ls find grep sed awk sort head tail '
                'cut tr date wc od timeout perl getent logger pstree ip '
                'modprobe insmod rmmod lsmod mkfs.ext4 dmesg blockdev truncate sha256sum').split()
    for binary in binaries:
        path = shutil.which(binary)
        if not path:
            raise RuntimeError(f'Missing prerequisite: {binary}')
        copy_binary(path)
    # marsadm uses only core Perl modules, including dynamically loaded extensions.
    inc = subprocess.check_output(['perl', '-MConfig', '-e',
                                   'print join("\n", @Config{qw(privlib archlib)})'], text=True)
    for directory in inc.splitlines():
        path = Path(directory)
        if path.is_dir():
            shutil.copytree(path, root / path.relative_to('/'), dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("CORE"))
            for extension in path.rglob('*.so'):
                copy_binary(extension)
    (root / 'etc/hostname').write_text('mars-test\n')
    (root / 'etc/hosts').write_text('127.0.0.1 localhost\n10.0.2.15 mars-test\n')
    (root / 'etc/nsswitch.conf').write_text('hosts: files\npasswd: files\ngroup: files\n')
    (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\n')
    (root / 'etc/group').write_text('root:x:0:\n')
    shutil.copy2(REPO / 'userspace/marsadm', root / 'usr/bin/marsadm')
    (root / 'usr/bin/marsadm').chmod(0o755)
    deps = subprocess.check_output(['modinfo', '-F', 'depends', str(source / 'kernel/mars.ko')], text=True).strip()
    for name in ['virtio_mmio', 'virtio_blk', 'virtio_net', 'ext4', 'crypto-crc32',
                 *filter(None, deps.split(','))]:
        result = subprocess.run(['modprobe', '--set-version', args.release, '--show-depends', name],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError(result.stderr)
        for line in result.stdout.splitlines():
            if line.startswith('insmod '):
                copy_file(line.split()[1])
    guest_modules = root / 'lib/modules' / args.release
    guest_modules.mkdir(parents=True, exist_ok=True)
    for name in ('modules.builtin', 'modules.builtin.modinfo', 'modules.order'):
        shutil.copy2(modules / name, guest_modules / name)
    shutil.copy2(source / 'kernel/mars.ko', guest_modules / 'mars.ko')
    run(['depmod', '-b', root, args.release])
    shutil.copy2(args.guest_script, root / 'init')
    (root / 'init').chmod(0o755)
    # Exit through QEMU's test device; microvm has no ACPI power controller.
    reboot = work / 'reboot.c'
    reboot.write_text('#include <unistd.h>\n#include <sys/io.h>\nint main(void) { sync(); if (ioperm(0xf4, 4, 1)) return 1; outl(0, 0xf4); return 1; }\n')
    run(['cc', '-Os', reboot, '-o', work / 'poweroff'])
    # This binary uses the same libc already copied with the shell.
    shutil.copy2(work / 'poweroff', root / 'usr/bin/poweroff')
    with (work / 'initramfs.cpio').open('wb') as archive:
        names = '\0'.join(str(p.relative_to(root)) for p in root.rglob('*')) + '\0'
        run(['cpio', '--null', '-o', '--format=newc', '--owner=0:0'], cwd=root,
            input=names.encode(), stdout=archive)
    with (work / 'initramfs.cpio').open('rb') as src:
        with gzip.open(work / 'initramfs.cpio.gz', 'wb') as dst:
            shutil.copyfileobj(src, dst)
    images = []
    for name, size in [('metadata', 32 * 1024**3), ('data', 128 * 1024**2)]:
        image = work / f'{name}.raw'
        with image.open('wb') as out:
            out.truncate(size)
        images.append(image)
    qemu = ['qemu-system-x86_64', '-machine', f'microvm,accel={args.accel},acpi=off,rtc=on',
            '-cpu', 'host' if args.accel == 'kvm' else 'max', '-m', '2048', '-smp', '2',
            '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
            '-nodefaults', '-no-reboot', '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
            '-kernel', modules / 'vmlinuz', '-initrd', work / 'initramfs.cpio.gz',
            '-append', 'console=ttyS0 rdinit=/init panic=-1 oops=panic loglevel=7 ' + args.append,
            '-netdev', 'user,id=net0', '-device', 'virtio-net-device,netdev=net0']
    for index, image in enumerate(images):
        qemu += ['-drive', f'if=none,id=d{index},format=raw,file={image}',
                 '-device', f'virtio-blk-device,drive=d{index}']
    (work / 'command.json').write_text(json.dumps([str(a) for a in qemu], indent=2))
    if args.prepare_only:
        return
    with (work / 'console.log').open('w') as log:
        try:
            result = subprocess.run([str(a) for a in qemu], stdout=log,
                                    stderr=subprocess.STDOUT, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f'Guest timed out; inspect {work / "console.log"}')
    console = (work / 'console.log').read_text(errors='replace')
    if result.returncode != 1 or 'MARS_QEMU_PASS' not in console or re.search(r'BUG:|WARNING: CPU:|Oops:|Kernel panic|Initramfs unpacking failed|MARS_QEMU_FAIL', console):
        raise RuntimeError(f'Guest failed; inspect {work / "console.log"}')
    print(f'PASS: {args.release}; log: {work / "console.log"}', flush=True)


if __name__ == '__main__':
    main()
