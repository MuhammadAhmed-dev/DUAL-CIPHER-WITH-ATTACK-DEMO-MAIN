#!/usr/bin/env python3
"""
Demo script for classroom presentation:
Shows step-by-step: plaintext -> normalization -> encryption -> decryption -> keys/info ->
known-plaintext attack -> frequency guess -> transposition demonstration -> benchmark comparison.

Updated: Adds TWO benchmark tables:
  - Benchmark A: two-stage (Vig->Shift) — attack expected to be successful
  - Benchmark B: three-stage (Vig->Transpose->Shift) — naive attack expected to fail (attack rate low/0)
"""

import time
from textwrap import fill

import cipher_logic
import attack_simulation
import frequency_analysis
import benchmarks

# -------------------------
# Helpers for pretty output
# -------------------------
def section(title):
    print("\n" + "=" * 8 + " " + title + " " + "=" * 8)

def show_kv(k, v):
    print(f"{k}: {v}")

def print_table(headers, rows):
    # equal column width based on contents
    col_widths = [max(len(h), max((len(str(r[i])) for r in rows), default=0)) + 2 for i, h in enumerate(headers)]
    header_line = " | ".join(h.center(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    print(header_line)
    print(sep_line)
    for r in rows:
        print(" | ".join(str(r[i]).rjust(col_widths[i]) for i in range(len(r))))

# -------------------------
# Demo parameters (editable)
# -------------------------
VIG_KEY = "NETWORKSECURITY"   # >= 10 chars as required
SHIFT_KEY = 7
TRANS_KEY = "43152"
AUTOKEY = False

PLAINTEXT = """This is a long test message for the custom cipher.
The Vigenere cipher, combined with a simple Caesar shift (and optional columnar transposition),
should provide a decent level of security against basic frequency analysis.
However, it is intentionally vulnerable to a known-plaintext attack for demonstration purposes."""
# known plaintext length attacker will use
KNOWN_LEN = min(len(VIG_KEY) * 2, 80)

# -------------------------
# 1) Plaintext & normalization
# -------------------------
def demo_plaintext():
    section("1) Original Plaintext")
    print("Full plaintext (snippet):")
    print(fill(PLAINTEXT.replace("\n", " "), width=80))
    norm = cipher_logic.normalize_text(PLAINTEXT, preserve_nonalpha=False)
    section("1.a) Normalized Plaintext (A-Z only)")
    print(norm[:500] + ("..." if len(norm) > 500 else ""))
    return norm

# -------------------------
# 2) Encrypt (Vig -> [Transpose] -> Shift)
# -------------------------
def demo_encrypt(plain, use_trans=False):
    section("2) Encryption (Vigenere -> Transposition -> Shift)")
    show_kv("Vigenere key", VIG_KEY)
    show_kv("Shift key", SHIFT_KEY)
    show_kv("Use transposition", use_trans)
    t0 = time.perf_counter()
    cipher = cipher_logic.encrypt_product(plain, VIG_KEY, SHIFT_KEY, transposition_key=TRANS_KEY, use_transposition=use_trans, autokey=AUTOKEY)
    t1 = time.perf_counter()
    show_kv("Ciphertext (snippet)", cipher[:200] + ("..." if len(cipher) > 200 else ""))
    show_kv("Encryption time (ms)", f"{(t1-t0)*1000:.3f}")
    return cipher

# -------------------------
# 3) Decrypt & verify
# -------------------------
def demo_decrypt(cipher, original_plain, use_trans=False):
    section("3) Decryption & Verification")
    t0 = time.perf_counter()
    recovered = cipher_logic.decrypt_product(cipher, VIG_KEY, SHIFT_KEY, transposition_key=TRANS_KEY, use_transposition=use_trans, autokey=AUTOKEY, preserve_nonalpha=False, original_plaintext=None)
    t1 = time.perf_counter()
    show_kv("Recovered (snippet)", recovered[:200] + ("..." if len(recovered) > 200 else ""))
    show_kv("Decryption time (ms)", f"{(t1-t0)*1000:.3f}")
    ok = cipher_logic.compare_texts(cipher_logic.normalize_text(original_plain), recovered)
    show_kv("Verification", "PASS" if ok else "FAIL")
    if not ok:
        print("NOTE: If verification fails, check keys and transposition settings.")
    return recovered

# -------------------------
# 4) Known-Plaintext Attack demo (single-case)
# -------------------------
def demo_known_plaintext_attack(cipher_segment, known_plain):
    section("4) Known-Plaintext Attack (single simulation)")
    show_kv("Known plaintext length", len(known_plain))
    print("Known plaintext snippet (attacker knows):")
    print(known_plain)
    t0 = time.perf_counter()
    shift_guess, vig_guess = attack_simulation.known_plaintext_attack(known_plain, cipher_segment, key_length=len(VIG_KEY))
    t1 = time.perf_counter()
    show_kv("Attack time (ms)", f"{(t1-t0)*1000:.3f}")
    if shift_guess is None:
        print("Attack failed to recover keys.")
        return None, None, 0.0
    show_kv("Recovered shift (attacker)", shift_guess)
    show_kv("Recovered Vigenere key (attacker)", vig_guess)
    # decrypt full ciphertext using recovered keys (assume no transposition)
    recovered_full = cipher_logic.decrypt_product(cipher_segment + "", vig_guess, shift_guess, transposition_key=TRANS_KEY, use_transposition=False, autokey=False)
    # compare with expected known_plain portion length vs full normalized plaintext
    matches = sum(1 for a, b in zip(recovered_full, cipher_logic.normalize_text(PLAINTEXT)) if a == b)
    total = len(cipher_logic.normalize_text(PLAINTEXT))
    acc = matches / total if total > 0 else 0.0
    show_kv("Recovered accuracy (matched letters of original full plain)", f"{matches} / {total} ({acc:.2%})")
    return shift_guess, vig_guess, acc

# -------------------------
# 4.b) Comparison: KPA on two-stage vs three-stage
# -------------------------
def demo_kpa_two_vs_three(plain):
    section("4.b) KPA COMPARISON: Two-stage (Vig->Shift) vs Three-stage (Vig->Transpose->Shift)")
    # prepare two-stage ciphertext (no transposition)
    two_stage = cipher_logic.shift_encrypt(cipher_logic.vigenere_encrypt(plain, VIG_KEY, autokey=AUTOKEY), SHIFT_KEY)
    # prepare three-stage ciphertext (with transposition)
    three_stage = cipher_logic.encrypt_product(plain, VIG_KEY, SHIFT_KEY, transposition_key=TRANS_KEY, use_transposition=True, autokey=AUTOKEY)

    print("\n-- Two-stage ciphertext (snippet) --")
    print(two_stage[:160] + ("..." if len(two_stage) > 160 else ""))
    print("\n-- Three-stage ciphertext (snippet) --")
    print(three_stage[:160] + ("..." if len(three_stage) > 160 else ""))

    # Attacker uses known plaintext (prefix)
    known_plain = plain[:KNOWN_LEN]
    cipher_segment_two = two_stage[:KNOWN_LEN]
    cipher_segment_three = three_stage[:KNOWN_LEN]

    # KPA on two-stage
    print("\nAttempting KPA on TWO-STAGE (should succeed):")
    t0 = time.perf_counter()
    s2, v2 = attack_simulation.known_plaintext_attack(known_plain, cipher_segment_two, key_length=len(VIG_KEY))
    t1 = time.perf_counter()
    if s2 is None:
        print("Two-stage KPA: FAILED to recover keys.")
    else:
        show_kv("Two-stage recovered shift", s2)
        show_kv("Two-stage recovered Vigenere key", v2)
        # decrypt full two-stage with recovered keys
        rec_full_two = cipher_logic.decrypt_product(two_stage, v2, s2, transposition_key=None, use_transposition=False, autokey=False)
        matches_two = sum(1 for a, b in zip(rec_full_two, plain) if a == b)
        acc_two = matches_two / len(plain) if len(plain) > 0 else 0.0
        show_kv("Two-stage KPA accuracy", f"{matches_two} / {len(plain)} ({acc_two:.2%})")
    show_kv("Two-stage KPA time (ms)", f"{(t1-t0)*1000:.3f}")

    # KPA on three-stage (naive)
    print("\nAttempting KPA on THREE-STAGE (naive KPA, should fail or be much worse):")
    t0 = time.perf_counter()
    s3, v3 = attack_simulation.known_plaintext_attack(known_plain, cipher_segment_three, key_length=len(VIG_KEY))
    t1 = time.perf_counter()
    if s3 is None:
        print("Three-stage KPA: FAILED to recover keys (as expected).")
    else:
        show_kv("Three-stage recovered shift", s3)
        show_kv("Three-stage recovered Vigenere key", v3)
        # if attacker attempts to decrypt three-stage as if it were two-stage, it will be wrong:
        rec_full_three_naive = cipher_logic.decrypt_product(three_stage, v3, s3, transposition_key=None, use_transposition=False, autokey=False)
        matches_three_naive = sum(1 for a, b in zip(rec_full_three_naive, plain) if a == b)
        acc_three_naive = matches_three_naive / len(plain) if len(plain) > 0 else 0.0
        show_kv("Three-stage naive KPA accuracy", f"{matches_three_naive} / {len(plain)} ({acc_three_naive:.2%})")
    show_kv("Three-stage KPA time (ms)", f"{(t1-t0)*1000:.3f}")

# -------------------------
# 5) Frequency analysis guess (outer shift)
# -------------------------
def demo_frequency_guess(cipher):
    section("5) Frequency-based Shift Guess")
    t0 = time.perf_counter()
    freq_guess = attack_simulation.frequency_based_shift_guess(cipher)
    t1 = time.perf_counter()
    show_kv("Frequency-based guessed shift", freq_guess)
    show_kv("Time (ms)", f"{(t1-t0)*1000:.3f}")
    # frequency report
    print("\nTop frequency report (first 8 entries):")
    freq = frequency_analysis.frequency_report(cipher)
    for i, (ch, cnt, pct) in enumerate(freq[:8], 1):
        print(f"  {i}. {ch} : {cnt} ({pct:.2%})")

# -------------------------
# 6) Small benchmark table (runs all at once)
# -------------------------
# def demo_benchmark(trials=3):
#     section("6) Small Benchmark (printed all at once)")
#     results = benchmarks.run_benchmarks(v_key=VIG_KEY, s_key=SHIFT_KEY, use_transposition=True, transposition_key=TRANS_KEY, autokey=AUTOKEY, trials=trials)
#     rows = []
#     for r in results:
#         rows.append((r["msg_len"], f"{r['avg_enc_ms']:.3f}", f"{r['avg_dec_ms']:.3f}", f"{r['avg_attack_ms']:.3f}", f"{r['attack_success_rate']:.2%}"))
#     headers = ["msg_len", "avg_enc_ms", "avg_dec_ms", "avg_attack_ms", "attack_success_rate"]
#     print_table(headers, rows)
#     print("\nSummary lines:")
#     for r in results:
#         print(f" - Message length {r['msg_len']}: avg_enc={r['avg_enc_ms']:.3f} ms, avg_dec={r['avg_dec_ms']:.3f} ms, avg_attack={r['avg_attack_ms']:.3f} ms, success_rate={r['attack_success_rate']:.2%}")

# -------------------------
# 7) NEW: Compare Benchmarks (Two-stage vs Three-stage)
# -------------------------
def demo_benchmark_compare(trials=3):
    section("6) BENCHMARK COMPARISON: Two-stage (attackable) vs Three-stage (with transposition)")
    # Run benchmarks for two-stage (no transposition) - attacker should succeed
    print("\n--- Benchmark A: TWO-STAGE (Vig->Shift) - attack expected to succeed ---")
    res_two = benchmarks.run_benchmarks(v_key=VIG_KEY, s_key=SHIFT_KEY, use_transposition=False, transposition_key=None, autokey=AUTOKEY, trials=trials)
    rows_two = []
    for r in res_two:
        rows_two.append((r["msg_len"], f"{r['avg_enc_ms']:.3f}", f"{r['avg_dec_ms']:.3f}", f"{r['avg_attack_ms']:.3f}", f"{r['attack_success_rate']:.2%}"))
    headers = ["msg_len", "avg_enc_ms", "avg_dec_ms", "avg_attack_ms", "attack_success_rate"]
    print_table(headers, rows_two)
    print("\nSummary (Two-stage):")
    for r in res_two:
        print(f" - Message length {r['msg_len']}: avg_enc={r['avg_enc_ms']:.3f} ms, avg_dec={r['avg_dec_ms']:.3f} ms, avg_attack={r['avg_attack_ms']:.3f} ms, success_rate={r['attack_success_rate']:.2%}")

    # Run benchmarks for three-stage (with transposition) - naive attack should drop
    print("\n--- Benchmark B: THREE-STAGE (Vig->Transpose->Shift) - attack expected to fail / low ---")
    res_three = benchmarks.run_benchmarks(v_key=VIG_KEY, s_key=SHIFT_KEY, use_transposition=True, transposition_key=TRANS_KEY, autokey=AUTOKEY, trials=trials)
    rows_three = []
    for r in res_three:
        rows_three.append((r["msg_len"], f"{r['avg_enc_ms']:.3f}", f"{r['avg_dec_ms']:.3f}", f"{r['avg_attack_ms']:.3f}", f"{r['attack_success_rate']:.2%}"))
    print_table(headers, rows_three)
    print("\nSummary (Three-stage):")
    for r in res_three:
        print(f" - Message length {r['msg_len']}: avg_enc={r['avg_enc_ms']:.3f} ms, avg_dec={r['avg_dec_ms']:.3f} ms, avg_attack={r['avg_attack_ms']:.3f} ms, success_rate={r['attack_success_rate']:.2%}")

# -------------------------
# Main demo runner
# -------------------------
def run_all():
    norm = demo_plaintext()
    cipher_with_trans = demo_encrypt(norm, use_trans=True)
    recovered = demo_decrypt(cipher_with_trans, PLAINTEXT, use_trans=True)
    demo_kpa_two_vs_three(norm)
    demo_frequency_guess(cipher_with_trans)
    # print the original single benchmark too (optional)
    #demo_benchmark(trials=2)
    # now the NEW comparison of two benchmark tables
    demo_benchmark_compare(trials=3)
    section("END OF DEMO")
    print("All steps completed. You may adjust parameters at the top of this script to demonstrate different scenarios.")

if __name__ == "__main__":
    run_all()
