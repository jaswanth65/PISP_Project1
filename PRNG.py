import hashlib
import hmac
import os
import time
import secrets

class CustomPRNG:
    def __init__(self):
        # Internal state used for generating randomness
        self.internal_state = None

    def initialize_seed(self, seed_input=None):
        """
        Initializes the PRNG with a seed value.
        If no seed is provided, uses system time and process ID for entropy.
        """
        if seed_input is None:
            seed_input = f"{time.time()}_{os.getpid()}_{secrets.token_hex(8)}"
        self.internal_state = hashlib.sha256(seed_input.encode()).digest()
        return seed_input

    def add_entropy(self, entropy_input=None):
        """
        Adds additional entropy to the internal state.
        """
        if self.internal_state is None:
            raise ValueError("PRNG not initialized. Call initialize_seed() first.")
        if entropy_input is None:
            entropy_input = secrets.token_bytes(16)
        self.internal_state = hashlib.sha256(self.internal_state + entropy_input).digest()

    def generate_number(self, output_size=8, deterministic=False):
        """
        Generates a pseudo-random number.
        If deterministic=True, output is based only on internal state.
        Otherwise, adds fresh entropy to the message.
        """
        if self.internal_state is None:
            raise ValueError("PRNG not initialized. Call initialize_seed() first.")
        message = b"generate"
        if not deterministic:
            message += secrets.token_bytes(16)
        output_block = hmac.new(self.internal_state, message, hashlib.sha256).digest()
        self.internal_state = hmac.new(self.internal_state, output_block, hashlib.sha256).digest()
        return int.from_bytes(output_block[:output_size], 'big')

# ------------------ Demonstration ------------------

if __name__ == "__main__":
    print("=== Random Output Test ===")
    prng_random = CustomPRNG()
    prng_random.initialize_seed()
    for i in range(2):
        print(f"Random Output {i+1}: {prng_random.generate_number()}")

    print("\n=== Deterministic Output Test ===")
    fixed_seed = "consistent_seed_001"
    prng_a = CustomPRNG()
    prng_b = CustomPRNG()
    prng_a.initialize_seed(fixed_seed)
    prng_b.initialize_seed(fixed_seed)
    sequence_a = [prng_a.generate_number(deterministic=True) for _ in range(2)]
    sequence_b = [prng_b.generate_number(deterministic=True) for _ in range(2)]
    print("Sequence A:", sequence_a)
    print("Sequence B:", sequence_b)

    print("\n=== Seeding Impact Test ===")
    prng_x = CustomPRNG()
    prng_y = CustomPRNG()
    prng_x.initialize_seed("seed_one")
    prng_y.initialize_seed("seed_two")
    sequence_x = [prng_x.generate_number(deterministic=True) for _ in range(2)]
    sequence_y = [prng_y.generate_number(deterministic=True) for _ in range(2)]
    print("Sequence X:", sequence_x)
    print("Sequence Y:", sequence_y)