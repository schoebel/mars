#!/bin/bash
#
# bauen von mars auf istore umgebung ...
# joerg.mann@1und1.de - at Do 27. Sep 14:47:33 CEST 2012


# aktuelles ulli zeugs holen ...
cd /home/test/work-mars-module-bauen
rm -rf sources
git clone ssh://git@git.schlund.de/multi-packages/ui-mars-multi.git /home/test/work-mars-module-bauen/sources/
cd sources
git pull

# gid-id die verwendet werden soll ...
CID="bad5c4f52724e2575187690875a6758481e216a7/WIP-3.2"
DIR="/home/test/work-mars-module-bauen/sources"

# host - auf dem ersten wird gebaut ! auf kernel-version achten !
#HST="ovzd-test-bs1:
#HST="ovzd-test-bap1:ovzd-test-lxa1:ovzd-test-bs2:ovzd-test-bap2:ovzd-test-lxa2"
HST="istore-test-bs7:istore-test-bap7"
HST="$HST:istore-test-bs3:istore-test-bs4:istore-test-bs5:istore-test-bs6"
HST="$HST:istore-test-bap3:istore-test-bap4:istore-test-bap5:istore-test-bap6"

# action ...
bash helper-scripts/create-multiple-new-versions $DIR $HST $CID
cd ..

