#!/usr/bin/env python3
import argparse
import time
import cipher_logic
import attack_simulation
import frequency_analysis
import benchmarks
from textwrap import shorten

def print_section(title):
    print("\n" + "="*len(title))
    print(title)
    print("="*len(title))

def demo(args):
    with open(args.plaintext_file, "r", encoding="utf-8") as f:
        original = f.read()
    normalized = cipher_logic.normalize_text(original, preserve_nonalpha=args.preserve_nonalpha)
    print_section("DEMO: Encryption / Decryption")
    print("Plaintext (snippet):", shorten(original.replace("\n", " "), width=200, placeholder="..."))
    print("Normalized (first 200 chars):", normalized[:200])
    start = time.perf_counter()
    ciphertext = cipher_logic.encrypt_product(normalized, args.vigenere_key, args.shift_key,
                                              transposition_key=args.transposition_key,
                                              use_transposition=args.use_transposition,
                                              autokey=args.autokey)
    enc_time = time.perf_counter() - start
    print(f"Ciphertext (snippet): {ciphertext[:200]}...")
    start = time.perf_counter()
    decrypted = cipher_logic.decrypt_product(ciphertext, args.vigenere_key, args.shift_key,
                                             transposition_key=args.transposition_key,
                                             use_transposition=args.use_transposition,
                                             autokey=args.autokey,
                                             preserve_nonalpha=args.preserve_nonalpha,
                                             original_plaintext=original)
    dec_time = time.perf_counter() - start
    print("Decrypted (snippet):", decrypted[:200] + ("..." if len(decrypted)>200 else ""))
    print(f"\\nEncryption time: {enc_time:.6f}s | Decryption time: {dec_time:.6f}s")
    ok = cipher_logic.compare_texts(cipher_logic.normalize_text(original), cipher_logic.normalize_text(decrypted))
    print("Verification:", "PASS" if ok else "FAIL")

def run_attack(args):
    with open(args.plaintext_file, "r", encoding="utf-8") as f:
        original = f.read()
    normalized = cipher_logic.normalize_text(original, preserve_nonalpha=args.preserve_nonalpha)
    ciphertext = cipher_logic.encrypt_product(normalized, args.vigenere_key, args.shift_key,
                                              transposition_key=args.transposition_key,
                                              use_transposition=args.use_transposition,
                                              autokey=args.autokey)
    print_section("ATTACK: Known-Plaintext Simulation")
    known_len = args.known_length
    known_plain = normalized[:known_len]
    cipher_segment = ciphertext[:known_len]
    print(f"Using known plaintext length = {known_len}")
    start = time.perf_counter()
    s_key, v_key = attack_simulation.known_plaintext_attack(known_plain, cipher_segment, key_length=len(args.vigenere_key))
    elapsed = time.perf_counter() - start
    if s_key is None:
        print("Attack failed to recover keys.")
    else:
        print(f"Recovered Shift Key: {s_key} (actual {args.shift_key})")
        print(f"Recovered Vigenere Key: {v_key} (actual {args.vigenere_key})")
    print(f"Attack Time: {elapsed:.6f}s")

    print_section("ATTACK: Frequency Analysis Attempt (outer-shift guess)")
    start = time.perf_counter()
    freq_result = attack_simulation.frequency_based_shift_guess(ciphertext)
    elapsed = time.perf_counter() - start
    print("Frequency-based guessed shift:", freq_result)
    print(f"Time: {elapsed:.6f}s")

def benchmark_cmd(args):
    print_section("BENCHMARK: Running experiments (this may take a moment)")
    results = benchmarks.run_benchmarks(
        v_key=args.vigenere_key, s_key=args.shift_key,
        use_transposition=args.use_transposition, transposition_key=args.transposition_key,
        autokey=args.autokey,
        trials=args.trials
    )
    # Print all benchmark results at once in a human-readable table
    headers = ["msg_len", "avg_enc_ms", "avg_dec_ms", "avg_attack_ms", "attack_success_rate"]
    # compute column widths
    col_widths = [max(len(h), 12) for h in headers]
    rows = []
    for row in results:
        rows.append([str(row["msg_len"]), f"{row['avg_enc_ms']:.3f}", f"{row['avg_dec_ms']:.3f}", f"{row['avg_attack_ms']:.3f}", f"{row['attack_success_rate']:.2%}"])
        for i, cell in enumerate(rows[-1]):
            if len(cell) + 2 > col_widths[i]:
                col_widths[i] = len(cell) + 2
    # header line
    line = " | ".join(h.center(col_widths[i]) for i, h in enumerate(headers))
    sep = "-+-".join('-'*col_widths[i] for i in range(len(headers)))
    print(line)
    print(sep)
    for r in rows:
        print(" | ".join(r[i].rjust(col_widths[i]) for i in range(len(r))))
    print_section("BENCHMARK: Summary")
    for row in results:
        print(f"Message length {row['msg_len']}: avg_enc={row['avg_enc_ms']:.3f} ms, avg_dec={row['avg_dec_ms']:.3f} ms, avg_attack={row['avg_attack_ms']:.3f} ms, attack_success_rate={row['attack_success_rate']:.2%}")

def build_parser():
    p = argparse.ArgumentParser(description="Enhanced CCP Product Cipher toolkit")
    p.add_argument("--vigenere-key", default="NETWORKSECURITY", help="Vigenere key (>=10 chars)")
    p.add_argument("--shift-key", type=int, default=7, help="Shift key (0-25)")
    p.add_argument("--plaintext-file", default="plain.txt", help="Path to plaintext file")
    p.add_argument("--preserve-nonalpha", action="store_true", help="Preserve non-alphabet characters in output (not used in internal normalization)")
    p.add_argument("--use-transposition", action="store_true", help="Use an additional columnar transposition stage (optional)")
    p.add_argument("--transposition-key", default="43152", help="Columnar transposition key (string of digits or letters)")
    p.add_argument("--autokey", action="store_true", help="Use autokey Vigenere mode (running key)")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Run encryption/decryption demo")
    atk = sub.add_parser("attack", help="Run attack simulations on sample file")
    atk.add_argument("--known-length", type=int, default=80, help="Known plaintext length for KPA")
    sub.add_parser("benchmark", help="Run benchmarks/experiments (outputs a readable table)")
    p.add_argument("--trials", type=int, default=5, help="Trials per message length for benchmark")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.cmd == "demo":
        demo(args)
    elif args.cmd == "attack":
        run_attack(args)
    elif args.cmd == "benchmark":
        benchmark_cmd(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
