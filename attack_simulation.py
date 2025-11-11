# attack_simulation.py - improved known-plaintext and frequency helpers
from collections import Counter

def known_plaintext_attack(known_plaintext, ciphertext, key_length=10):
    """Try to recover shift (Caesar) and repeating Vigenere key of length key_length.
    Returns (shift_guess, key_string) or (None, None).
    Assumes known_plaintext aligns with start of ciphertext segment provided.
    """
    known_plaintext = "".join(filter(str.isalpha, known_plaintext)).upper()
    ciphertext = "".join(filter(str.isalpha, ciphertext)).upper()
    if len(known_plaintext) == 0 or len(ciphertext) == 0:
        return (None, None)
    n = min(len(known_plaintext), len(ciphertext))
    combined_shifts = [ (ord(ciphertext[i]) - ord(known_plaintext[i])) % 26 for i in range(n) ]
    for s_key_guess in range(26):
        vig_shifts = [ (cs - s_key_guess) % 26 for cs in combined_shifts ]
        if len(vig_shifts) < key_length*2:
            continue
        seg1 = vig_shifts[:key_length]
        seg2 = vig_shifts[key_length:key_length*2]
        if seg1 == seg2:
            key = ''.join(chr(s + ord('A')) for s in seg1)
            return (s_key_guess, key)
    return (None, None)

def frequency_based_shift_guess(ciphertext):
    text = "".join(filter(str.isalpha, ciphertext)).upper()
    if not text:
        return None
    freq = Counter(text)
    most_common = freq.most_common(1)[0][0]
    shift_guess = (ord(most_common) - ord('E')) % 26
    return shift_guess
