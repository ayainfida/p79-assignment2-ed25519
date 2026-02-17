import argparse
from ed25519 import ED25519, ED25519ScalarMultAlgorithm, Message

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Demo Ed25519 signature generation and verification.")
    parser.add_argument('--f', action='store_true', help='Use fast point addition')
    args = parser.parse_args()

    if args.f:
        algo = ED25519ScalarMultAlgorithm.FAST_SCALAR_MULT
        print("Using fast point addition.")
    else:
        algo = ED25519ScalarMultAlgorithm.SCALAR_MULT
        print("Using standard point addition.")

    ed25519_instance = ED25519(algo)

    alice_sk = ed25519_instance.generate_private_key()
    alice_pk = ed25519_instance.derive_public_key(alice_sk)

    message = Message(b"Hello, Bob! This is Alice.")
    signature = ed25519_instance.sign(message, alice_sk)

    print("Alice's Public Key: ", alice_pk.key_bytes.hex())
    print("Signature: ", signature.signature_bytes.hex())

    assert ed25519_instance.verify(message, signature, alice_pk), "Signature verification failed!"
                                