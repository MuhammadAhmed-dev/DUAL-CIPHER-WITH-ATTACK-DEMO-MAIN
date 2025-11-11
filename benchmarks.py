# benchmarks.py - benchmarking utilities (renamed)
# Original author: adapted from provided benchmark.py
import time, random
import cipher_logic, attack_simulation

def random_english_like_text(n):
    letters = "etaoinshrdlucmwfgypbvkjxqz"
    return "".join(random.choice(letters) for _ in range(n)).upper()

def run_single_trial(msg_len, v_key, s_key, use_transposition=False, transposition_key=None, autokey=False):
    plaintext = random_english_like_text(msg_len)
    start = time.perf_counter()
    ciphertext = cipher_logic.encrypt_product(plaintext, v_key, s_key, transposition_key=transposition_key, use_transposition=use_transposition, autokey=autokey)
    enc_time = (time.perf_counter() - start) * 1000.0
    start = time.perf_counter()
    decrypted = cipher_logic.decrypt_product(ciphertext, v_key, s_key, transposition_key=transposition_key, use_transposition=use_transposition, autokey=autokey, preserve_nonalpha=False, original_plaintext=None)
    dec_time = (time.perf_counter() - start) * 1000.0
    known_len = min(len(v_key)*2, len(plaintext))
    known_plain = plaintext[:known_len]
    cipher_segment = ciphertext[:known_len]
    start = time.perf_counter()
    recovered = attack_simulation.known_plaintext_attack(known_plain, cipher_segment, key_length=len(v_key))
    attack_time = (time.perf_counter() - start) * 1000.0
    success = (recovered[0] is not None)
    return enc_time, dec_time, attack_time, success

def run_benchmarks(v_key="NETWORKSECURITY", s_key=7, use_transposition=False, transposition_key=None, autokey=False, trials=5):
    lengths = [50,100,200,500]
    results = []
    for L in lengths:
        encs=[]; decs=[]; atks=[]; succs=[]
        for _ in range(trials):
            e,d,a,s = run_single_trial(L, v_key, s_key, use_transposition=use_transposition, transposition_key=transposition_key, autokey=autokey)
            encs.append(e); decs.append(d); atks.append(a); succs.append(1 if s else 0)
        results.append({
            "msg_len": L,
            "avg_enc_ms": sum(encs)/len(encs),
            "avg_dec_ms": sum(decs)/len(decs),
            "avg_attack_ms": sum(atks)/len(atks),
            "attack_success_rate": sum(succs)/len(succs)
        })
    return results
