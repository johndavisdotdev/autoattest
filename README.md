# autoattest

`autoattest` checks that an Intel TDX confidential VM and its attached NVIDIA
GPUs are running under Confidential Compute protection. It runs a full
attestation and prints a single **SAFE** / **NOT SAFE** verdict. The process
follows the [VoltageGPU confidential VM guide](https://docs.voltagegpu.com/pods/confidential-vm).

## Attestation process

Each run generates a fresh 32-byte nonce and binds every piece of evidence to
it:

1. **Intel TDX (confidential VM)**
   - Generates a TD quote through `configfs-tsm`, with `report_data = SHA-512(nonce)`.
   - Verifies the quote against the pinned Intel SGX Root CA, using collateral
     and CRLs from Intel PCS. The TCB status must be `UpToDate`.
   - Fails if the TD is running in debug mode.

2. **NVIDIA GPU (local checks)**
   - Requires CC mode **ON**, DevTools mode **OFF**, and environment **PROD**.
   - Requests each GPU's attestation report over the nonce, then verifies the
     report signature and certificate chain locally against the pinned NVIDIA
     Device Identity CA.

3. **NVIDIA Remote Attestation Service (NRAS)**
   - Submits the GPU evidence to NRAS and verifies the returned EAT token: its
     ES384 signature (keys come from the NRAS JWKS), the issuer, and the nonce.
   - Requires `measres=success`, `secboot=true` and `dbgstat=disabled`, and
     every verifier claim must pass: report cert chain, report signature, and
     the driver and VBIOS RIMs.

The verdict is SAFE only if at least one check passed and no check failed.

Both trust anchors are compiled into the binary and pinned by SHA-256
fingerprint (see `attest/roots.go`).

## Requirements

- Run it inside a TDX confidential VM, as root, because `configfs-tsm`
  requires root.
- The NVIDIA driver must be loaded (the tool uses NVML).
- The VM needs outbound HTTPS access to Intel PCS and NVIDIA NRAS.

## Build

```sh
make build   # builds ./autoattest, stamped with version/commit/date from git
make dist    # builds dist/autoattest_<version>_<arch>.deb (installs /usr/bin/autoattest)
make test
make clean
```

The version comes from `git describe`; override it with `make dist VERSION=v1.0.0`.
A C toolchain is required because NVML is accessed through cgo.

## Usage

```sh
# Run a full attestation and print a human-readable report
sudo ./autoattest

# Also show informational lines and the TD measurements (MRTD, RTMRs, MRSEAM)
sudo ./autoattest -v

# Print the report as JSON (stdout always holds exactly one JSON document)
sudo ./autoattest --json | jq .safe

# Save the raw evidence (TDX quote, GPU reports and cert chains, NRAS response, report.json)
sudo ./autoattest -e ./evidence

# Use a longer timeout and an NRAS service key
sudo AUTOATTEST_NRAS_SERVICE_KEY=... ./autoattest --timeout 5m
```

The exit status is `0` only when every check passes, so you can use the tool in
scripts:

```sh
sudo ./autoattest --json > report.json || echo "environment is NOT safe"
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-v, --verbose` | `false` | Show informational lines and TD measurements |
| `-j, --json` | `false` | Emit the report as JSON |
| `-e, --evidence-dir` | | Directory to save raw evidence in |
| `--timeout` | `2m` | Overall timeout for the run |
| `--nras-url` | `https://nras.attestation.nvidia.com/v3/attest/gpu` | NRAS GPU endpoint |
| `--claims-version` | `2.0` | NRAS EAT claims version |
| `--nras-service-key` | | Optional NVIDIA attestation service key |
| `--tdx-device` | `/dev/tdx_guest` | TDX guest device |
| `--configfs-root` | `/sys/kernel/config/tsm/report` | configfs-tsm report directory |
| `--config` | | Config file path |

### Configuration

You can also set any flag in a YAML config file or with an environment
variable:

- **Config file:** `$HOME/.autoattest.yaml` or `./.autoattest.yaml`, or pass a
  path with `--config`. Keys use the flag names.
- **Environment:** add the `AUTOATTEST_` prefix, upper-case the flag name and
  replace dashes with underscores, for example `AUTOATTEST_NRAS_SERVICE_KEY`.
  Pass the service key this way instead of as a flag.

```yaml
# ~/.autoattest.yaml
timeout: 5m
evidence-dir: /var/lib/autoattest
```

## Testing

```sh
go test ./...
```
