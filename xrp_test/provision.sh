#!/bin/bash
#
# Provision an Ubuntu 20.04 CloudLab machine for the WiredTiger B-tree XRP
# pushdown. Mirrors the setup used on clnode292 (Micron) and flex01 (Optane).
#
# usage: provision.sh <wiredtiger-xrp-dir> <linux-bpfof-dir> [--skip-kernel]
#
# Stages:
#   1. userspace deps: libbpf 0.1.0 (the stock debs the XRP artifact used),
#      autotools
#   2. XRP header shim: the kernel tree's uapi linux/bpf.h (defines
#      BPF_PROG_TYPE_XRP and struct bpf_xrp) exposed via -I outside the
#      system include path
#   3. kernel: build and install the fd-array-fixed XRP kernel
#      (5.12.0-xrp-xrp-fdfix) and make it the grub default; REBOOT REQUIRED
#      before XRP works
#   4. WiredTiger + BPF program + test tools
#
# After reboot, create test databases on the NVMe under test, e.g.:
#   ./create_db /nvme/wt_home2 1000000
#   ./rw_bench  /nvme/wt_home4 init 10000000 16
set -eux -o pipefail

WT_DIR=$(realpath "$1")
KSRC=$(realpath "$2")
SKIP_KERNEL=${3:-}
WTX=/mydata/wtx

sudo mkdir -p $WTX/include/linux
sudo chown -R "$(whoami)" $WTX

# stage 1: userspace dependencies
wget -q -O /tmp/libbpf0.deb https://old-releases.ubuntu.com/ubuntu/pool/universe/libb/libbpf/libbpf0_0.1.0-1_amd64.deb
wget -q -O /tmp/libbpf-dev.deb https://old-releases.ubuntu.com/ubuntu/pool/universe/libb/libbpf/libbpf-dev_0.1.0-1_amd64.deb
sudo dpkg -i /tmp/libbpf0.deb /tmp/libbpf-dev.deb
sudo apt-get install -y -qq autoconf automake libtool clang llvm libelf-dev flex bison libssl-dev bc dwarves

# stage 2: XRP header shim
cp "$KSRC"/include/uapi/linux/bpf.h $WTX/include/linux/bpf.h
grep -q bpf_xrp $WTX/include/linux/bpf.h

# stage 3: kernel (the fd-array fix in fs/read_write.c is required for plain
# read_xrp; without it every request dies with EOPNOTSUPP)
if [ "$SKIP_KERNEL" != "--skip-kernel" ]; then
    cd "$KSRC"
    if [ -f /boot/config-"$(uname -r)" ]; then
        cp /boot/config-"$(uname -r)" .config
    fi
    scripts/config --set-str CONFIG_LOCALVERSION "-xrp-fdfix"
    scripts/config --disable CONFIG_LOCALVERSION_AUTO
    scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
    scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""
    make olddefconfig
    make -j"$(nproc)"
    sudo make modules_install
    sudo make install
    # keep the kernel printk spam from filling small root filesystems
    sudo bash -c 'printf ":msg, contains, \"nvme_handle_cqe\" stop\n" > /etc/rsyslog.d/10-drop-xrp-spam.conf'
    sudo systemctl restart rsyslog || true
    echo "kernel installed, reboot into the -xrp-fdfix entry before testing"
fi

# stage 4: WiredTiger, BPF program, test tools
cd "$WT_DIR"
./autogen.sh
CPPFLAGS="-I$WTX/include" ./configure --enable-silent-rules
make -j"$(nproc)"
cd bpf_prog
make wt_btree_bpf.o BPF_CFLAGS="-I$WTX/include"
cd ../xrp_test
make XRP_INC=$WTX/include

echo PROVISION_OK
