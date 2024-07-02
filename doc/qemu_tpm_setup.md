
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

Login using `fedora/fedora` and run few tests

### Testing TPM device

Sanity checks

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

[fedora@fed38 ~]$ sudo tpm2_getcap algorithms | grep -A 9 'sha384'
sha384:
  value:      0xC
  asymmetric: 0
  symmetric:  0
  hash:       1
  object:     0
  reserved:   0x0
  signing:    0
  encrypting: 0
  method:     0
```

Working with Keys, from <https://github.com/tpm2-software/tpm2-openssl/blob/master/docs/keys.md>

```bash
[fedora@fed38 ~]$ sudo tpm2_createek -G rsa -c ek_rsa.ctx
[fedora@fed38 ~]$ sudo tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa --ak-context ak_rsa.ctx
loaded-key:
  name: 000b42319d115beaaa57c3f2b385d8cb1e2e6834b65e5da97be1e8339a74a053d7ff
  qualified name: 000b1f2b91b573baeb8d3e37b9ce48eafb0542bde0ff2fac9366f31bf178680440e6
[fedora@fed38 ~]$ sudo tpm2_evictcontrol --object-context=ak_rsa.ctx 0x81000000
persistent-handle: 0x81000000
action: persisted

[fedora@fed38 ~]$ sudo tpm2_getcap handles-persistent
- 0x81000000

[fedora@fed38 ~]$ sudo tpm2_evictcontrol --hierarchy=o --object-context=0x81000000
persistent-handle: 0x81000000
action: evicted
[fedora@fed38 ~]$ sudo tpm2_getcap handles-persistent
[fedora@fed38 ~]$

# Primary key generation

[fedora@fed38 ~]$ sudo tpm2_createprimary --hierarchy=o --hash-algorithm=sha256 --key-algorithm=ecc256:aes128cfb --key-context=tpm_primary_key.ctx --attributes="decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted" -V
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt
  raw: 0x30472
type:
  value: ecc
  raw: 0x23
curve-id:
  value: NIST p256
  raw: 0x3
kdfa-alg:
  value: null
  raw: 0x10
kdfa-halg:
  value: (null)
  raw: 0x0
scheme:
  value: null
  raw: 0x10
scheme-halg:
  value: (null)
  raw: 0x0
sym-alg:
  value: aes
  raw: 0x6
sym-mode:
  value: cfb
  raw: 0x43
sym-keybits: 128
x: 50ae5635be637d617fb1d9499fda0b618b63e8f27cc750ec65bcb9d9655e08e2
y: 531a72b1039f2441bfb59f9086119b0c50d3fa7acd86d432325dd8726b4b22e6
[fedora@fed38 ~]$ sudo tpm2_evictcontrol --hierarchy=o 0x81020004 --object-context=tpm_primary_key.ctx -V
persistent-handle: 0x81020004
action: persisted
[fedora@fed38 ~]$ sudo tpm2_getcap handles-persistent
- 0x81000000
- 0x81020004

# TPM ECDSA key generation (Device attestation key)

[fedora@fed38 ~]$ sudo tpm2_create --parent-context=0x81020004 --hash-algorithm=sha256 --key-algorithm=ecc256:ecdsa-sha256 --public=tpm_ecdsa_pub.key --private=tpm_ecdsa_priv.key --attributes="sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda"
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|sign
  raw: 0x40472
type:
  value: ecc
  raw: 0x23
curve-id:
  value: NIST p256
  raw: 0x3
kdfa-alg:
  value: null
  raw: 0x10
kdfa-halg:
  value: (null)
  raw: 0x0
scheme:
  value: ecdsa
  raw: 0x18
scheme-halg:
  value: sha256
  raw: 0xb
sym-alg:
  value: null
  raw: 0x10
sym-mode:
  value: (null)
  raw: 0x0
sym-keybits: 0
x: 66d3f05041cd5b39ee5bb191ea1b1b61dfdb1d31040a3742c47db1395eb997e9
y: 6a70ed0b486dd094a4bf37a2ef8051cc71c81c6e760025086f8bd44751bb690f

[fedora@fed38 ~]$ sudo tpm2_load --public=tpm_ecdsa_pub.key --private=tpm_ecdsa_priv.key --key-context tpm_ecdsa_key.ctx --parent-context=0x81020004
name: 000b47b51aa53335f1521b45382f194d4ca9291daee4ba3d4f9191bbdf56e789c61f

[fedora@fed38 ~]$ sudo tpm2_evictcontrol --hierarchy=o 0x81000002 --object-context=tpm_ecdsa_key.ctx -V
persistent-handle: 0x81000002
action: persisted

# Flushing memory

[fedora@fed38 ~]$ sudo tpm2_flushcontext --transient-object -V
INFO on line: "44" in file: "lib/tpm2_capability.c": GetCapability: capability: 0x1, property: 0x80000000

```
