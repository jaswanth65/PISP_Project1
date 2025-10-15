import hashlib

def simple_kdf(shared_secret: int, iterations: int) -> str:

    key_material = str(shared_secret).encode()

    for i in range(iterations):
        key_material = hashlib.sha256(key_material).digest()
        if i % (iterations // 10 or 1) == 0:
            print(f"Iteration {i+1}: {key_material.hex()}")

    return key_material.hex()

if __name__ == "__main__":
    print("=== Key Derivation Function (KDF) ===")
    try:
        shared_secret_input = int(input("Enter the shared secret from Diffie-Hellman exchange: "))
        iterations_input = int(input("Enter number of hash iterations (e.g., 10000): "))
    except ValueError:
        print("Invalid input. Please enter numeric values only.")
        exit()

    derived_key = simple_kdf(shared_secret_input, iterations_input)
    print("\n Final Derived Encryption Key:")
    print(derived_key)