# CCP Product Cipher - Corrected Package

## What this package contains
- `cipher_logic.py` : corrected encryption/decryption (Vigenere + optional columnar transposition + Caesar shift).
- `attack_simulation.py` : known-plaintext attack and frequency-based outer shift guess.
- `frequency_analysis.py` : frequency report utility.
- `benchmarks.py` : benchmarking utilities (renamed from benchmark.py).
- `main.py` : CLI entrypoint (demo, attack, benchmark).
- `plain.txt` : sample plaintext.
- `tests/` : sample unit tests (not included by default).

## Quick usage
Run demo (prints sections as requested):
```bash
python main.py demo --plaintext-file plain.txt --vigenere-key NETWORKSECURITY --shift-key 7 --use-transposition --transposition-key 43152
```

Run attack simulation:
```bash
python main.py attack --plaintext-file plain.txt --vigenere-key NETWORKSECURITY --shift-key 7 --use-transposition --known-length 80
```

Run benchmark (CSV-like output):
```bash
python main.py --trials 5 benchmark
```

## Notes
- `encrypt_product` enforces Vigenere key length >= 10 (per assignment).
- If you want a zip with sample outputs or extra tests, tell me and I will include them.
