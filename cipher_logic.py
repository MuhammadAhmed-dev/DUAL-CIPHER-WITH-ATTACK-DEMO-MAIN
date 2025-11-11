# cipher_logic.py - corrected and robust implementation
from collections import defaultdict

def normalize_text(text, preserve_nonalpha=False):
    """Normalize text:
    - preserve_nonalpha=False: return A-Z-only uppercase string.
    - preserve_nonalpha=True: return original string uppercased (non-alpha preserved).
    """
    if preserve_nonalpha:
        return ''.join(c.upper() for c in text)
    return ''.join([c.upper() for c in text if c.isalpha()])

def compare_texts(a, b):
    return a == b

def _vigenere_key_stream(key, plaintext=None, autokey=False):
    key = "".join(filter(str.isalpha, key)).upper()
    if not autokey:
        while True:
            for c in key:
                yield c
    else:
        for c in key:
            yield c
        if plaintext:
            for c in plaintext:
                yield c

def vigenere_encrypt(plaintext, key, autokey=False):
    plaintext = normalize_text(plaintext, preserve_nonalpha=False)
    key = "".join(filter(str.isalpha, key)).upper()
    ks = _vigenere_key_stream(key, plaintext, autokey=autokey)
    ciphertext = []
    for p in plaintext:
        k = next(ks)
        p_val = ord(p) - ord('A')
        k_val = ord(k) - ord('A')
        ciphertext.append(chr(((p_val + k_val) % 26) + ord('A')))
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key, autokey=False):
    ciphertext = normalize_text(ciphertext, preserve_nonalpha=False)
    key = "".join(filter(str.isalpha, key)).upper()
    plaintext = []
    if not autokey:
        ks = _vigenere_key_stream(key, None, autokey=False)
        for c in ciphertext:
            k = next(ks)
            p_val = (ord(c)-ord('A') - (ord(k)-ord('A')) + 26) % 26
            plaintext.append(chr(p_val + ord('A')))
        return ''.join(plaintext)
    else:
        ks = list(key)
        for c in ciphertext:
            k = ks.pop(0)
            p_val = (ord(c)-ord('A') - (ord(k)-ord('A')) + 26) % 26
            pch = chr(p_val + ord('A'))
            plaintext.append(pch)
            ks.append(pch)
        return ''.join(plaintext)

def shift_encrypt(plaintext, shift):
    plaintext = normalize_text(plaintext, preserve_nonalpha=False)
    ciphertext = []
    for c in plaintext:
        v = ord(c) - ord('A')
        ciphertext.append(chr(((v + shift) % 26) + ord('A')))
    return ''.join(ciphertext)

def shift_decrypt(ciphertext, shift):
    ciphertext = normalize_text(ciphertext, preserve_nonalpha=False)
    plaintext = []
    for c in ciphertext:
        v = ord(c) - ord('A')
        plaintext.append(chr(((v - shift + 26) % 26) + ord('A')))
    return ''.join(plaintext)

def _column_order_indices(key):
    key_str = str(key)
    return [i for ch, i in sorted([(ch, i) for i, ch in enumerate(key_str)])]

def columnar_transpose_encrypt(text, key):
    text = normalize_text(text, preserve_nonalpha=False)
    key_str = str(key)
    klen = len(key_str)
    if klen == 0:
        return text
    pad_len = (-len(text)) % klen
    text_padded = text + ('X' * pad_len)
    rows = [text_padded[i:i+klen] for i in range(0, len(text_padded), klen)]
    order = _column_order_indices(key_str)
    out = []
    for col in order:
        for r in rows:
            out.append(r[col])
    return ''.join(out)

def columnar_transpose_decrypt(text, key):
    key_str = str(key)
    klen = len(key_str)
    if klen == 0:
        return text
    order = _column_order_indices(key_str)
    rows_count = len(text) // klen
    grid = [['']*klen for _ in range(rows_count)]
    pos = 0
    for col in order:
        for r in range(rows_count):
            grid[r][col] = text[pos]
            pos += 1
    out = []
    for r in range(rows_count):
        out.extend(grid[r])
    return ''.join(out).rstrip('X')

def encrypt_product(plaintext, vigenere_key, shift_key, transposition_key=None, use_transposition=False, autokey=False):
    # Validate vigenere key length per assignment
    if len(''.join(filter(str.isalpha, vigenere_key))) < 10:
        raise ValueError("Vigenere key must be >= 10 alphabetic characters (per assignment)." )
    p = normalize_text(plaintext, preserve_nonalpha=False)
    i = vigenere_encrypt(p, vigenere_key, autokey=autokey)
    if use_transposition and transposition_key:
        i = columnar_transpose_encrypt(i, transposition_key)
    c = shift_encrypt(i, shift_key)
    return c

def decrypt_product(ciphertext, vigenere_key, shift_key, transposition_key=None, use_transposition=False, autokey=False, preserve_nonalpha=False, original_plaintext=None):
    i = shift_decrypt(ciphertext, shift_key)
    if use_transposition and transposition_key:
        i = columnar_transpose_decrypt(i, transposition_key)
    p = vigenere_decrypt(i, vigenere_key, autokey=autokey)
    if preserve_nonalpha and original_plaintext is not None:
        res = []
        letters = list(p)
        for ch in original_plaintext:
            if ch.isalpha():
                res.append(letters.pop(0))
            else:
                res.append(ch)
        return ''.join(res)
    return p
