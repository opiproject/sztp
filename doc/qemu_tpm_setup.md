
# OPI QEMU TPM2 setup

## Docs

- See <https://en.opensuse.org/Software_TPM_Emulator_For_QEMU>
- See <https://github.com/qemu/qemu/blob/master/docs/specs/tpm.rst#the-qemu-tpm-emulator-device>
- See <https://tpm2-software.github.io/2020/10/19/TPM2-Device-Emulation-With-QEMU.html>

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
qemu-system-x86_64 -smp 2 -cdrom init.iso -m 1G \
  -drive file=guest_os_image.qcow2,if=none,id=disk \
  -device ide-hd,drive=disk,bootindex=0 \
  -chardev socket,id=chrtpm,path=/tmp/emulated_tpm/swtpm-sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -qmp tcp:localhost:4444,server,wait=off \
  --nographic
```

Login using fedora/fedora and run few tests

```bash
[fedora@fed38 ~]$ dmesg | grep -i tpm
[    0.055889] ACPI: TPM2 0x000000003FFD1EED 00004C (v04 BOCHS  BXPC     00000001 BXPC 00000001)
[    0.056104] ACPI: Reserving TPM2 table memory at [mem 0x3ffd1eed-0x3ffd1f38]
[    3.401305] tpm_tis MSFT0101:00: 2.0 TPM (device-id 0x1, rev-id 1)

[fedora@fed38 ~]$ ls -l /dev/tpm*
crw-rw----. 1 tss  root  10,   224 Jun 18 23:17 /dev/tpm0
crw-rw----. 1 root tss  253, 65536 Jun 18 23:17 /dev/tpmrm0

[fedora@fed38 ~]$ sudo tpm2_clear
[fedora@fed38 ~]$ sudo tpm2_selftest
```
