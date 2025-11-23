# rsa_sign_encrypt_demo.py
# Demonstrates RSA sign-then-encrypt and verify for given small parameters.

from math import gcd

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m

def demo():
    # Given values
    Bob_N = 143     # 11 * 13
    Bob_e = 7
    Alice_N = 39    # 3 * 13
    Alice_e = 5
    M = 3

    # Compute phi and private exponents
    # For small example we can factor the moduli manually:
    # Bob_N = 143 = 11 * 13 --> phi = (11-1)*(13-1) = 10*12 = 120
    Bob_phi = 120
    Bob_d = modinv(Bob_e, Bob_phi)

    # Alice: 39 = 3 * 13 -> phi = (3-1)*(13-1) = 2*12 = 24
    Alice_phi = 24
    Alice_d = modinv(Alice_e, Alice_phi)

    print("Keys and parameters:")
    print(f" Bob public key: (N={Bob_N}, e={Bob_e})")
    print(f" Bob phi(N) = {Bob_phi}, Bob private d = {Bob_d}")
    print(f" Alice public key: (N={Alice_N}, e={Alice_e})")
    print(f" Alice phi(N) = {Alice_phi}, Alice private d = {Alice_d}")
    print()

    # Bob signs message M with his private key: s = M^d mod N_bob
    s = pow(M, Bob_d, Bob_N)
    print(f"Bob signs message M={M}: signature s = M^d mod Bob_N = {s}")

    # Bob encrypts the signature s under Alice's public key: c = s^{e_A} mod Alice_N
    c = pow(s, Alice_e, Alice_N)
    print(f"Bob encrypts signature under Alice's public key: c = s^eA mod Alice_N = {c}")

    # Alice receives ciphertext c. She decrypts with her private key to recover signature s'
    s_recovered = pow(c, Alice_d, Alice_N)
    print(f"Alice decrypts: s' = c^dA mod Alice_N = {s_recovered}")

    # Alice verifies the signature: compute s'^eB mod Bob_N and check equals M
    verification = pow(s_recovered, Bob_e, Bob_N)
    print(f"Alice computes verification value: (s')^eB mod Bob_N = {verification}")

    if verification == M:
        print("Signature verification successful: verification == M")
    else:
        print("Signature verification FAILED: verification != M")

    # Summary
    print("\nSummary of numeric values:")
    print(f" M = {M}")
    print(f" s (computed by Bob) = {s}")
    print(f" c (sent to Alice) = {c}")
    print(f" s_recovered (after Alice decrypt) = {s_recovered}")
    print(f" verification = {verification}")

if __name__ == "__main__":
    demo()
