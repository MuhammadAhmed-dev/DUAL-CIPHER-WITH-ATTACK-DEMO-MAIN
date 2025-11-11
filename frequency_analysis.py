# frequency_analysis.py - frequency report utility
from collections import Counter

def frequency_report(ciphertext):
    text = "".join(filter(str.isalpha, ciphertext)).upper()
    counts = Counter(text)
    total = sum(counts.values())
    report = [(ch, counts[ch], counts[ch]/total if total>0 else 0.0) for ch in sorted(counts, key=counts.get, reverse=True)]
    return report
