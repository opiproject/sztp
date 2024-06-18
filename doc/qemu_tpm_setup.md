
# OPI QEMU TPM2 setup

## Docs

- From <https://tpm2-software.github.io/2020/10/19/TPM2-Device-Emulation-With-QEMU.html>

## Virtualization support

Make sure that VT-x/AMD-v support is enabled in BIOS

```bash
$ lscpu | grep -i virtualization
Virtualization:                  VT-x
```

and that kvm modules are loaded

```bash
$ lsmod | grep -i kvm
kvm_intel             217088  0
kvm                   614400  1 kvm_intel
irqbypass              16384  1 kvm
```

## Tool installation

Installation on Fedora

```bash
sudo dnf install qemu-kvm swtpm wget genisoimage
```

or on Ubuntu

```bash
sudo apt install qemu-system swtpm wget genisoimage
```

## Download guest image

get

```bash
wget -O guest_os_image.qcow2 https://download.fedoraproject.org/pub/fedora/linux/releases/38/Cloud/x86_64/images/Fedora-Cloud-Base-38-1.6.x86_64.qcow2
```

check

```bash
$ qemu-img info guest_os_image.qcow2
image: guest_os_image.qcow2
file format: qcow2
virtual size: 5 GiB (5368709120 bytes)
disk size: 503 MiB
cluster_size: 65536
Format specific information:
    compat: 0.10
    refcount bits: 16
```

## Change password

```bash
cat <<- EOF > meta-data
instance-id: iid-local01;
local-hostname: fed38;
EOF

cat <<- EOF > user-data
#cloud-config
password: fedora
chpasswd: { expire: False }
ssh_pwauth: True
EOF

genisoimage -output init.iso -volid cidata -joliet -rock user-data meta-data
```

## TPM emulation

```bash
mkdir /tmp/emulated_tpm
swtpm socket --tpmstate dir=/tmp/emulated_tpm --ctrl type=unixio,path=/tmp/emulated_tpm/swtpm-sock --log level=20 --tpm2
```

### Run qemu with TPM device

```bash
qemu-system-x86_64 -smp 2 -cdrom init.iso -m 1G -drive file=guest_os_image.qcow2,if=none,id=disk -device ide-hd,drive=disk,bootindex=0 --nographic
```

Login using fedora/fedora and run few tests

```bash
[fedora@fed38 ~]$ dmesg | grep -i tpm
[    4.061037] ima: No TPM chip found, activating TPM-bypass!
[    6.204763] systemd[1]: systemd 253.2-1.fc38 running in system mode (+PAM +AUDIT +SELINUX -APPARMOR +IMA +SMACK +SECCOMP -GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN)
[   43.258954] systemd[1]: systemd 253.2-1.fc38 running in system mode (+PAM +AUDIT +SELINUX -APPARMOR +IMA +SMACK +SECCOMP -GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN)
[   51.961877] systemd[1]: systemd-pcrmachine.service - TPM2 PCR Machine ID Measurement was skipped because of an unmet condition check (ConditionPathExists=/sys/firmware/efi/efivars/StubP.

[fedora@fed38 ~]$ ls -l /dev/tpm*
ls: cannot access '/dev/tpm*': No such file or directory
```
