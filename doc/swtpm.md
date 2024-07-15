# OPI SW TPM2 emulation setup

For QEMU, check [this page](./qemu_tpm_setup.md)

## Docs

- See <https://github.com/stefanberger/swtpm>
- See <https://github.com/lf-edge/eve/blob/master/tests/tpm/prep-and-test.sh>

## Installation

```bash
sudo apt-get install swtpm tpm2-tools -y
```

## Run SWTPM Emulation TCP

use TCP to connect to this emulation

```bash
mkdir /tmp/emulated_tpm
swtpm socket --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --tpmstate dir=/tmp/emulated_tpm \
    --log file="swtpm.log" \
    --log level=20 \
    --flags not-need-init,startup-clear
```

Set Transmission Interface (TCTI) swtpm socket, so tpm2-tools use it instead of the default char device interface.

```bash
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
```

## Run SWTPM Emulation Unix socket

use unix socket to connect to this emulation

```bash
mkdir /tmp/emulated_tpm
swtpm socket --tpm2 \
    --server type=unixio,path=/tmp/emulated_tpm/swtpm.sock \
    --ctrl type=unixio,path=/tmp/emulated_tpm/swtpm.sock.ctrl \
    --tpmstate dir=/tmp/emulated_tpm \
    --log file="swtpm.log" \
    --log level=20 \
    --flags not-need-init,startup-clear
```

Set Transmission Interface (TCTI) swtpm socket, so tpm2-tools use it instead of the default char device interface.

```bash
export TPM2TOOLS_TCTI="swtpm:path=/tmp/emulated_tpm/swtpm.sock"
```

## Testing TPM2

keys

```bash
# start fresh
tpm2 clear

# create Endorsement Key
tpm2 createek -c ek.ctx

# this setup seems very fragile, and quickly errors out with
# "out of memory for object contexts", so flush everything to be safe.
tpm2 flushcontext -t
tpm2 flushcontext -l
tpm2 flushcontext -s

# create Storage Root Key
tpm2 startauthsession --policy-session -S session.ctx
tpm2 policysecret -S session.ctx -c $ENDO_SEED
tpm2 create -C ek.ctx -P "session:session.ctx" -G rsa2048 -u srk.pub -r srk.priv \
            -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth'
tpm2 flushcontext session.ctx
tpm2 flushcontext -t
tpm2 flushcontext -l
tpm2 flushcontext -s

# load the srk
tpm2 startauthsession --policy-session -S session.ctx
tpm2 policysecret -S session.ctx -c $ENDO_SEED
tpm2 load -C ek.ctx -P "session:session.ctx" -u srk.pub -r srk.priv -c srk.ctx
tpm2 flushcontext session.ctx
tpm2 flushcontext -t
tpm2 flushcontext -l
tpm2 flushcontext -s

# make persisted know-good-handles out of ek and srk
tpm2 evictcontrol -C o -c ek.ctx $EK_HANDLE
tpm2 evictcontrol -C o -c srk.ctx $SRK_HANDLE

# clean up
rm session.ctx ek.ctx srk.pub srk.priv srk.ctx

# just dump persistent handles, good for debugging§
tpm2 getcap handles-persistent
```
