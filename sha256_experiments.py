# sha256_experiments.py
# Usage: python sha256_experiments.py
# Requires: numpy, matplotlib (for plotting)
import hashlib
import random
import time
from math import comb
import numpy as np
import matplotlib.pyplot as plt
import csv

def generate_inputs(count: int):
    # Unique-ish inputs: use counter + random 32-bit integer
    for i in range(count):
        yield f"{i}-{random.getrandbits(64)}".encode('utf-8')

def count_ones_in_hex_hash(hex_digest: str) -> int:
    # Convert hex digest to bytes then count set bits
    b = bytes.fromhex(hex_digest)
    # np.unpackbits for speed if processing many items
    return int(np.sum(np.unpackbits(np.frombuffer(b, dtype=np.uint8))))

def run_histogram(num_inputs=10000, save_csv=None):
    counts = []
    start = time.time()
    for data in generate_inputs(num_inputs):
        h = hashlib.sha256(data).hexdigest()
        ones = count_ones_in_hex_hash(h)
        counts.append(ones)
    elapsed = time.time() - start
    hash_rate = num_inputs / elapsed if elapsed > 0 else float('inf')

    # Statistics
    unique, freq = np.unique(counts, return_counts=True)
    mean = np.mean(counts)
    std = np.std(counts)

    print(f"Inputs: {num_inputs}")
    print(f"Elapsed time: {elapsed:.4f} s")
    print(f"Hash rate: {hash_rate:.2f} hashes/s")
    print(f"Mean 1-bits: {mean:.3f}, Std dev: {std:.3f}")

    # Save CSV if requested
    if save_csv:
        with open(save_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ones_count', 'frequency'])
            for u, fcount in zip(unique, freq):
                writer.writerow([u, fcount])
        print(f"Saved counts to {save_csv}")

    # Plot histogram
    plt.figure(figsize=(10,5))
    plt.bar(unique, freq)
    plt.xlabel('Number of 1-bits')
    plt.ylabel('Frequency')
    plt.title('SHA-256 1-Bit Count Distribution')
    plt.grid(True, linestyle=':', linewidth=0.5)
    plt.tight_layout()
    plt.show()

    return {
        'num_inputs': num_inputs,
        'elapsed': elapsed,
        'hash_rate': hash_rate,
        'mean_ones': mean,
        'std_ones': std,
        'unique_counts': unique,
        'frequencies': freq
    }

def estimate_attack_times(hash_rate):
    # Work sizes:
    # Birthday attack (weak collision resistance) ~ 2^(n/2) where n=256 -> 2^128
    # Brute-force (preimage) attack ~ 2^256
    two128 = 2 ** 128
    two256 = 2 ** 256
    seconds_in_year = 3600 * 24 * 365.25
    time_birthday_years = two128 / hash_rate / seconds_in_year
    time_bruteforce_years = two256 / hash_rate / seconds_in_year
    return time_birthday_years, time_bruteforce_years

def probability_exact_k(total_bits=256, k_values=(128, 100)):
    res = {}
    for k in k_values:
        # Avoid computing extremely large comb directly without using Python's big ints (Python supports big ints)
        p = comb(total_bits, k) / (2 ** total_bits)
        res[k] = p
    return res

def main():
    num_inputs = int(input("Number of distinct inputs to generate (e.g., 10000): ").strip() or "10000")
    results = run_histogram(num_inputs=num_inputs, save_csv="sha256_ones_counts.csv")

    birthday_years, brute_years = estimate_attack_times(results['hash_rate'])
    print(f"\nEstimated time for birthday attack (2^128 hashes): {birthday_years:.3e} years")
    print(f"Estimated time for brute-force attack (2^256 hashes): {brute_years:.3e} years")

    # Probabilities for exact counts
    k1 = int(input("Enter k1 to compute P(X=k1) (e.g., 128): ").strip() or "128")
    k2 = int(input("Enter k2 to compute P(X=k2) (e.g., 100): ").strip() or "100")
    probs = probability_exact_k(256, (k1, k2))
    print(f"\nProbability exactly {k1} 1-bits: {probs[k1]:.5e}")
    print(f"Probability exactly {k2} 1-bits: {probs[k2]:.5e}")

if __name__ == "__main__":
    main()
