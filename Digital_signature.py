import hashlib
import random
from math import gcd

# ------------------ Prime Generation ------------------

def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(start=200, end=300):
    while True:
        candidate = random.randint(start, end)
        if is_prime(candidate):
            return candidate

# ------------------ Modular Inverse ------------------

def modinv(a, m):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Error in generating the inverse')
    return x % m

# ------------------ Key Generation ------------------

def Key():
    p = generate_prime()
    q = generate_prime()
    while p == q:
        q = generate_prime()
    
    N = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randrange(3, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi)
    
    d = modinv(e, phi)
    return (e, N), (d, N)

# ------------------ Hash Function ------------------

def H(M):
    hash_value = int.from_bytes(hashlib.sha256(M.encode()).digest(), byteorder='big')
    return hash_value

# ------------------ Signature Function ------------------

def Sign(private_key, M):
    d, N = private_key
    hash_val = H(M)
    signature = pow(hash_val, d, N)
    return signature

# ------------------ Verification Function ------------------

def Verify(public_key, M, signature):
    e, N = public_key
    hash_val = H(M)
    verified_val = pow(signature, e, N)
    return 1 if verified_val == hash_val % N else 0

# ------------------ User Prompt Verification ------------------

def select_and_verify(alice_public, bob_public, message, signature):
    print("Select the public key to verify the signature:")
    print("1 - Alice's Public Key")
    print("2 - Bob's Public Key")
    
    try:
        choice = int(input("Enter your choice (1 or 2): "))
    except ValueError:
        print("Invalid input. Please enter a number.")
        return 0

    if choice == 1:
        print("Using Alice's public key for verification.")
        result = Verify(alice_public, message, signature)
        return result
    elif choice == 2:
        print("Using Bob's public key for verification.")
        result = Verify(bob_public, message, signature)
        return result
    else:
        print("Invalid selection. No verification performed.")
        return 0

# ------------------ Main Execution ------------------

if __name__ == "__main__":
    # Generate keys for Alice and Bob
    alice_public, alice_private = Key()
    bob_public, bob_private = Key()

    print("Alice's Public Key:", alice_public)
    print("Bob's Public Key:", bob_public)

    # Message and signature
    message = "Hi Bob, How are you?"
    signature = Sign(alice_private, message)
    print("\nMessage:", message)
    print("Alice's Signature:", signature)

    # User selects key for verification
    verification_result = select_and_verify(alice_public, bob_public, message, signature)
    print("Verification Result:", verification_result)