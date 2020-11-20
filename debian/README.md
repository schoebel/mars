Building the dkms package:

```
user@plug:/home/user/$ git clone https://github.com/fgbreel/mars.git && cd mars

user@plug:/home/user/mars$ git checkout debian/sid

user@plug:/home/user/mars$ gbp buildpackage --git-pristine-tar --git-pristine-tar-commit --git-upstream-tag='mars%(version)s' --git-debian-branch=debian/sid -us -uc
gbp:info: Creating /home/user/mars_0.1astable114.orig.tar.gz
gbp:info: Performing the build
 dpkg-buildpackage -us -uc -ui -i -I
dpkg-buildpackage: info: source package mars
dpkg-buildpackage: info: source version 0.1astable114-1
dpkg-buildpackage: info: source distribution unstable
dpkg-buildpackage: info: source changed by Gabriel Francisco <frc.gabriel@gmail.com>
 dpkg-source -i -I --before-build .
dpkg-buildpackage: info: host architecture amd64
 fakeroot debian/rules clean
dh clean --with dkms
   debian/rules override_dh_auto_clean
make[1]: Entering directory '/home/user/mars'
make[1]: Leaving directory '/home/user/mars'
   dh_clean
 dpkg-source -i -I -b .
dpkg-source: info: using source format '3.0 (quilt)'
dpkg-source: info: building mars using existing ./mars_0.1astable114.orig.tar.gz
dpkg-source: info: building mars in mars_0.1astable114-1.debian.tar.xz
dpkg-source: info: building mars in mars_0.1astable114-1.dsc
 debian/rules build
dh build --with dkms
   dh_update_autotools_config
   dh_autoreconf
   create-stamp debian/debhelper-build-stamp
 fakeroot debian/rules binary
dh binary --with dkms
   dh_testroot
   dh_prep
   debian/rules override_dh_install
make[1]: Entering directory '/home/user/mars'
cp debian/mars-Makefile kernel/Makefile
cp debian/mars-Kbuild kernel/Kbuild
dh_install scripts/gen_config.pl usr/src/mars-0.1astable114/
dh_install kernel/* usr/src/mars-0.1astable114/
make[1]: Leaving directory '/home/user/mars'
   dh_installdocs
   dh_installchangelogs
   dh_installman
   dh_installcron
   debian/rules override_dh_dkms
make[1]: Entering directory '/home/user/mars'
dh_dkms -V 0.1astable114
make[1]: Leaving directory '/home/user/mars'
   dh_perl
   dh_link
   dh_strip_nondeterminism
   dh_compress
   dh_fixperms
   dh_missing
   dh_strip
   dh_makeshlibs
   dh_shlibdeps
   dh_installdeb
   dh_gencontrol
   dh_md5sums
   dh_builddeb
dpkg-deb: building package 'mars-dkms' in '../mars-dkms_0.1astable114-1_amd64.deb'.
dpkg-deb: building package 'mars-tools' in '../mars-tools_0.1astable114-1_amd64.deb'.
 dpkg-genbuildinfo
 dpkg-genchanges  >../mars_0.1astable114-1_amd64.changes
dpkg-genchanges: info: including full source code in upload
 dpkg-source -i -I --after-build .
dpkg-buildpackage: info: full upload (original source is included)
```

Installing on target computer:

```
root@plug:/home/user# apt install ./mars-dkms_0.1astable114-1_amd64.deb
Reading package lists... Done
Building dependency tree
Reading state information... Done
Note, selecting 'mars-dkms' instead of './mars-dkms_0.1astable114-1_amd64.deb'
The following NEW packages will be installed:
  mars-dkms
0 upgraded, 1 newly installed, 0 to remove and 100 not upgraded.
Need to get 0 B/223 kB of archives.
After this operation, 1144 kB of additional disk space will be used.
Get:1 /home/user/mars-dkms_0.1astable114-1_amd64.deb mars-dkms amd64 0.1astable114-1 [223 kB]
Selecting previously unselected package mars-dkms.
(Reading database ... 222033 files and directories currently installed.)
Preparing to unpack .../mars-dkms_0.1astable114-1_amd64.deb ...
Unpacking mars-dkms (0.1astable114-1) ...
Setting up mars-dkms (0.1astable114-1) ...
Loading new mars-0.1astable114 DKMS files...
Building for 4.9.0-13-amd64
Building initial module for 4.9.0-13-amd64
Done.

mars.ko:
Running module version sanity check.
 - Original module
   - No original module exists within this kernel
 - Installation
   - Installing to /lib/modules/4.9.0-13-amd64/updates/dkms/

depmod...

DKMS: install completed.

root@plug:/home/user# stat /lib/modules/4.9.0-13-amd64/updates/dkms/mars.ko
  File: /lib/modules/4.9.0-13-amd64/updates/dkms/mars.ko
  Size: 861440    	Blocks: 1688       IO Block: 4096   regular file
Device: fe01h/65025d	Inode: 525826      Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2020-11-19 18:20:55.082662798 +0100
Modify: 2020-11-19 18:20:54.862664958 +0100
Change: 2020-11-19 18:20:54.862664958 +0100
 Birth: -
```

Return from `dmesg` from target computer:

```
root@plug:/home/user# fallocate -l 10G foo
root@plug:/home/user# losetup -f foo
root@plug:/home/user# vgcreate mars /dev/loop0
root@plug:/home/user# lvcreate -n mars -L 9G mars
root@plug:/home/user# mkfs -t ext4 /dev/mapper/mars-mars
root@plug:/home/user# mount /dev/mapper/mars-mars /mars/
root@plug:/home/user# modprobe mars

root@plug:/home/user# dmesg  | tail
[44413.535164] Cluster UUID is missing. Mount /mars/, and/or say {create,join}-cluster afterwwards.
[44413.535172] loading MARS, BUILDTAG=no-buildtag-available BUILDHOST=user@plug BUILDDATE=2020-11-20 03:31:33
[44413.590445] crc32c     digest duration =     56001256 ns
[44413.633954] crc32      digest duration =     44000989 ns
[44413.929130] sha1       digest duration =    296006661 ns
[44414.185517] md5old     digest duration =    256005761 ns
[44414.449394] md5        digest duration =    264005939 ns
[44414.484375] lzo      compress duration =     36000810 ns
[44414.526621] lz4      compress duration =     40000900 ns
[44415.499954] zlib     compress duration =    976021964 ns
```
