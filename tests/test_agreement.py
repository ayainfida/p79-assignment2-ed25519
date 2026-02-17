import unittest
from os import urandom
from ed25519 import ED25519, ED25519ScalarMultAlgorithm, Message

class TestX25519Agreement(unittest.TestCase):
    def setUp(self):
        # Set up ED25519 instances for both both scalar multiplication choices
        self.ed25519 = ED25519(ED25519ScalarMultAlgorithm.SCALAR_MULT)
        self.ed25519_fast = ED25519(ED25519ScalarMultAlgorithm.FAST_SCALAR_MULT)
        self.runs = 20 # Number of iterations for random tests

    """
    Test Ed25519 scalar multiplication agreement on the public key derived from the same private key.
    Since base point is valid, both algorithms should yield the same scalar multiplication result, thus the same public key. 
    """
    def test_agreement_on_public_key(self):
        # Derive public keys from the same private key using both point addition methods and check if they match
        for _ in range(self.runs):
            sk = self.ed25519.generate_private_key()
            pk_1 = self.ed25519.derive_public_key(sk)
            pk_2 = self.ed25519_fast.derive_public_key(sk)
            self.assertEqual(pk_1, pk_2)

    """
    Test Ed25519 Signature agreement generated from the same private key and message.
    """
    def test_signature_agreement_with_random_keys(self):
        # Test Ed25519 signature agreement on random messages and keys, ensuring both algorithms produce the same shared secret
        for _ in range(self.runs):
            sk = self.ed25519.generate_private_key()
            # Generate a random message between 0 to 2048 bytes to test with
            msg_num_bytes = int(urandom(2).hex(), 16) % 2049
            msg = Message(urandom(msg_num_bytes))
            sig_1 = self.ed25519.sign(msg, sk)
            sig_2 = self.ed25519_fast.sign(msg, sk)

            # Both signatures should be the same since they are derived from the same private key and message
            self.assertEqual(sig_1, sig_2)

    """
    Test that signatures generated from the same private key and message are valid and can be verified by both algorithms.
    """
    def test_signature_verification_agreement(self):
        for _ in range(self.runs):
            sk = self.ed25519.generate_private_key()
            pk = self.ed25519.derive_public_key(sk)

            # Generate a random message between 0 to 2048 bytes to test with    
            msg_num_bytes = int(urandom(2).hex(), 16) % 2049
            msg = Message(urandom(msg_num_bytes))
            sig = self.ed25519.sign(msg, sk)

            # Both algorithms should verify the same signature successfully
            self.assertTrue(self.ed25519.verify(msg, sig, pk))
            self.assertTrue(self.ed25519_fast.verify(msg, sig, pk))    

if __name__ == "__main__":
    unittest.main()