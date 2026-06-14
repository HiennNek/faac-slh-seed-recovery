# FAAC SLH Seed Brute-Force Tools

GPU (CUDA) and CPU (OpenMP) brute-force tools to recover the **seed** used by FAAC SLH rolling-code keyfobs, given one or more captured RF frames and the manufacturer key.

## See TUTORIAL.md for instruction

## How FAAC SLH Encryption Works

FAAC SLH is a KeeLoq-based rolling code protocol. Each transmission is 64 bits:

```
|--------- Fix (32 bits) ----------|--------- Hop (32 bits) ----------|
|  Serial (28 bits)  | Btn (4 bits) |   KeeLoq-encrypted counter      |
```

- **Fix**: Transmitted in the clear — contains serial number and button ID.
- **Hop**: Encrypted using a **device key** unique to the remote.
- **Device key**: Derived from the **seed** and the **manufacturer key (mfkey)** via:
  ```
  device_key = encrypt(seed, mfkey) << 32 | encrypt((seed>>16)|0x544D, mfkey)
  ```
- **Seed**: A 32-bit random value exchanged once between remote and receiver during pairing. Never transmitted again — must be brute-forced.

### Validation

Each captured frame's `hop` is decrypted with a candidate `device_key`. The decrypted value must have its top 12 bits match specific nibbles of the `fix` (positions depend on counter parity). This gives ~11 bits of constraint per frame:

- **3 frames (different buttons)**: ~33 bits → **unique seed** (100% confidence)
- **2 frames (different buttons)**: ~22 bits → **~1,000 candidates**
- **2 frames (same button)**: ~22 bits → **~1,000 candidates**
- **1 frame**: ~11 bits → **~1,000,000 candidates** (too many)

When 2 frames use the **same button**, they likely come from consecutive presses, so the counters should be close. Candidates are sorted by `|counter2 - counter1|` (gap), putting the most likely first.

## Prerequisites

### GPU version (`faac_gpu`)

- **NVIDIA GPU** with Compute Capability 5.0+ (tested on MX250, sm_61)
- **CUDA Toolkit** (tested with 12.5)
- **Compiler**: `clang++` (recommended if nvcc fails with modern GCC) or `nvcc`

### CPU version (`faac_bf`)

- **GCC** with OpenMP support
- Significantly slower than GPU (~hours vs minutes)

## Compilation

```bash
# GPU version (clang++ — recommended if nvcc fails on modern systems)
clang++ --cuda-gpu-arch=sm_61 -O3 -o faac_gpu faac_slh_bruteforce_gpu.cu -L/opt/cuda/lib64 -lcuda -lcudart

# GPU version (nvcc)
nvcc -O3 -o faac_gpu faac_slh_bruteforce_gpu.cu

# CPU version
gcc -O3 -fopenmp -lm -o faac_bf faac_slh_bruteforce_seed.c
```

**Note**: If using clang++, adjust `--cuda-gpu-arch=` to match your GPU. Common values: `sm_61` (GTX 1050/1060, MX250), `sm_75` (RTX 20xx), `sm_86` (RTX 30xx).

## Usage

```bash
./faac_gpu <mfkey_hex> <frame1_hex> [frame2_hex ... frameN_hex]
./faac_bf  <mfkey_hex> <frame1_hex> [frame2_hex ... frameN_hex]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `mfkey_hex` | Manufacturer key in hex (16 hex digits, e.g. `53696C7669618C14`) |
| `frameN_hex` | Captured frame in hex (16 hex digits = 64 bits) |

### Examples

```bash
# 3 frames — unique result
./faac_gpu 53696C7669618C14 A0CE0C75E0B64119 A0CE0C75AB79166A A0AB0BD18A0AE46C

# 2 frames, same button — sorted by counter gap
./faac_gpu 53696C7669618C14 A0982456DC19B919 A0982456CFDB0B45

# 2 frames, different buttons — sorted by seed
./faac_gpu 53696C7669618C14 A03A05283CFAA63B A03A0529CDD23073

# 1 frame — count only
./faac_gpu 53696C7669618C14 A0CE0C75E0B64119
```

## Output

### Terminal

- **3+ frames**: Prints the unique seed with 100% confidence.
- **2 frames (same button)**: Shows top 50 candidates sorted by counter gap (smaller = more likely). The first candidate typically has overwhelming confidence (e.g., 87% vs 1% for runner-up).
- **2 frames (different buttons)**: Shows top 50 candidates sorted by seed value.
- **1 frame**: Prints candidate count only.

### Report File (`FAACBF_REPORT_<timestamp>.txt`)

A full report is always saved with the complete candidate list, including:

- MFKey and frame data used
- Search mode and timing
- Total candidates found and effective bits determined
- Full sorted list of all candidates with decrypted per-frame data

## Interpreting Results

With the standard FAAC SLH manufacturer key `53696C7669618C14`

- If your remote validates — the seed is found and you can create compatible remotes.
- If **no candidates** are found — your installation uses a **different manufacturer key** (batch-specific). The mfkey cannot be recovered from RF captures alone; you would need access to the receiver during pairing.

### Same-Button Gap Sorting

When 2 frames use the same button, the scoring formula is:

```
score = 1 / (1 + gap/10)
percentage = score / sum(all_scores) * 100
```

A gap of 1 (consecutive presses) gives ~87% when there are ~1000 candidates. A gap of 1000 drops to ~1%.

## Protocol Reference

| Component | Value |
|-----------|-------|
| Encryption | KeeLoq NLF (`0x3A5C742E`), 528 rounds |
| Learning | `faac_learning(seed, mfkey)` |
| Frame size | 64 bits (32 fix + 32 hop) |
| Fix layout | `serial << 4 \| btn` |
| Hop layout | KeeLoq-encrypted `(nibble_check << 20) \| counter` |
| Counter bits | 20 |
| Nibble check (even counter) | fix nibbles[6,7,5] |
| Nibble check (odd counter) | fix nibbles[2,3,4] |
| Keys in official firmware | `53696C7669618C14` (type 5, FAAC SLH) |
