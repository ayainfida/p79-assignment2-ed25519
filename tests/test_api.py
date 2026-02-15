import unittest
from os import urandom
from ed25519.defaults import q
from ed25519.primitives import LengthError
from ed25519.encoding import encode_little_endian
from ed25519 import ED25519, PrivateKey, PublicKey, Signature, Message

class TestED25519Boundary(unittest.TestCase):
    def setUp(self):
        self.ed25519_instance = ED25519()
    """
    A good API should validate input lengths and types.
    These tests ensure that the ED25519 methods raise appropriate exceptions when an invalid input is given.
    """

    def test_private_key_length(self):
        # Test if private key given is not 32 bytes raises LengthError for incorrect lengths and works for correct length

        # 1) Not 32 bytes, should raise LengthError
        with self.assertRaises(LengthError):
            self.ed25519_instance.derive_public_key(PrivateKey(b'\x11' * 31))
        with self.assertRaises(LengthError):
            self.ed25519_instance.derive_public_key(PrivateKey(b'\x22' * 33))

        # 2) Empty byte string, should raise LengthError
        with self.assertRaises(LengthError):
            self.ed25519_instance.derive_public_key(PrivateKey(b''))
    
        # 3) Valid length (32 bytes), should not raise
        pk = self.ed25519_instance.derive_public_key(PrivateKey(b'\x11' * 32))
        self.assertIsInstance(pk, PublicKey)

    def test_key_type_validation(self):
        # Test that providing incorrect types to the methods raises TypeError

        # 1) derive_public_key should only accept PrivateKey objects, and raise TypeError if it is not given a PrivateKey
        with self.assertRaises(TypeError):
            self.ed25519_instance.derive_public_key("not a private key")  # type: ignore
        with self.assertRaises(TypeError):
            self.ed25519_instance.derive_public_key(PublicKey(b'\x22' * 32))  # type: ignore
        with self.assertRaises(TypeError):
            self.ed25519_instance.derive_public_key(urandom(32))  # type: ignore
        # Valid instance should not raise
        self.ed25519_instance.derive_public_key(PrivateKey(b'\x00' * 32)) 

        # 2) sign should raise TypeError if sk is not a PrivateKey
        with self.assertRaises(TypeError):
            self.ed25519_instance.sign(Message(b"test message"), "not a private key")  # type: ignore
        with self.assertRaises(TypeError):
            self.ed25519_instance.sign(Message(b"test message"), self.ed25519_instance.derive_public_key(self.ed25519_instance.generate_private_key()))  # type: ignore
        with self.assertRaises(TypeError):
            self.ed25519_instance.sign(Message(b"test message"), urandom(32))  # type: ignore
        # Valid instance should not raise
        self.ed25519_instance.sign(Message(b"test message"), self.ed25519_instance.generate_private_key())

        # 3) verify should raise TypeError if public key is not given
        sk = self.ed25519_instance.generate_private_key()
        pk = self.ed25519_instance.derive_public_key(sk)
        msg = Message(b"p79-assignment-2")
        signature = self.ed25519_instance.sign(msg, sk)
        with self.assertRaises(TypeError):
            self.ed25519_instance.verify(msg, signature, "not a public key")  # type: ignore
        with self.assertRaises(TypeError):
            self.ed25519_instance.verify(msg, signature, self.ed25519_instance.generate_private_key())  # type: ignore
        with self.assertRaises(TypeError):
            self.ed25519_instance.verify(msg, signature, urandom(32))  # type: ignore
        # Valid instance should not raise
        self.assertTrue(self.ed25519_instance.verify(msg, signature, pk))
    
    def test_signature_length_validation(self):
        # Test that providing a signature of incorrect length raises LengthError
        sk = self.ed25519_instance.generate_private_key()
        pk = self.ed25519_instance.derive_public_key(sk)
        msg = Message(b"p79-assignment-2")
        valid_signature = self.ed25519_instance.sign(msg, sk)
  
        # 1) Signature not 64 bytes should raise LengthError
        with self.assertRaises(LengthError):
            self.ed25519_instance.verify(msg, Signature(b'\x33' * 63), pk)
        with self.assertRaises(LengthError):
            self.ed25519_instance.verify(msg, Signature(b'\x44' * 65), pk)
        
        # 2) Empty signature should raise LengthError
        with self.assertRaises(LengthError):
            self.ed25519_instance.verify(msg, Signature(b''), pk)

        # 3) Valid signature length should not raise
        self.assertTrue(self.ed25519_instance.verify(msg, valid_signature, pk))
    
    def test_modified_signature_verification(self): # Unforgeability test
        # Test that an invalid signature fails verification
        sk = self.ed25519_instance.generate_private_key()
        pk = self.ed25519_instance.derive_public_key(sk)
        msg = Message(b"p79-assignment-2")
        valid_signature = self.ed25519_instance.sign(msg, sk)

        # Modify the valid signature to make it invalid (e.g., change one byte)
        invalid_signature_bytes = bytearray(valid_signature.signature_bytes)
        invalid_signature_bytes[0] ^= 0xFF 
        invalid_signature = Signature(bytes(invalid_signature_bytes))

        # The invalid signature should fail verification with the correct public key
        self.assertFalse(self.ed25519_instance.verify(msg, invalid_signature, pk))

        # Modifying the second half of the signature (t) so that it is not a valid scalar mod q should also fail verification
        invalid_signature_bytes = bytearray(valid_signature.signature_bytes)
        invalid_signature_bytes[32:] = encode_little_endian(q)  # Set t to a value that is not a valid scalar mod q
        invalid_signature = Signature(bytes(invalid_signature_bytes))
        self.assertFalse(self.ed25519_instance.verify(msg, invalid_signature, pk))
    
    def test_signature_verification_with_wrong_public_key(self): # Authenticity test
        # Test that a valid signature fails verification if the wrong public key is used
        sk1 = self.ed25519_instance.generate_private_key()
        pk1 = self.ed25519_instance.derive_public_key(sk1)
        sk2 = self.ed25519_instance.generate_private_key()
        pk2 = self.ed25519_instance.derive_public_key(sk2)

        msg = Message(b"p79-assignment-2")
        signature = self.ed25519_instance.sign(msg, sk1)

        # The signature should fail verification with the wrong public key
        self.assertFalse(self.ed25519_instance.verify(msg, signature, pk2))

        # The signature should verify successfully with the correct public key
        self.assertTrue(self.ed25519_instance.verify(msg, signature, pk1))
    
    def test_signature_non_collision(self):
        # Test that two different messages signed with the same private key produce different signatures
        sk1 = self.ed25519_instance.generate_private_key()

        msg1 = Message(b"p79-assignment-2")
        msg2 = Message(b"p79-assignment-2 with a twist")

        signature11 = self.ed25519_instance.sign(msg1, sk1)
        signature12 = self.ed25519_instance.sign(msg2, sk1)

        self.assertNotEqual(signature11.signature_bytes, signature12.signature_bytes)

        # Test that signing the same message with different private keys produces different signatures
        sk2 = self.ed25519_instance.generate_private_key()

        signature21 = self.ed25519_instance.sign(msg1, sk2)
        signature22 = self.ed25519_instance.sign(msg2, sk2)

        # The two signatures should be different
        self.assertNotEqual(signature11.signature_bytes, signature21.signature_bytes)
        self.assertNotEqual(signature12.signature_bytes, signature22.signature_bytes)

    def test_modified_message(self): # Integrity test
        sk = self.ed25519_instance.generate_private_key()
        pk = self.ed25519_instance.derive_public_key(sk)
        msg = Message(b"p79-assignment-2")
        signature = self.ed25519_instance.sign(msg, sk)

        # Modify the message to make it different
        modified_msg = Message(b"p79-assignment-2 with a twist")
        # The signature should fail verification with the modified message
        self.assertFalse(self.ed25519_instance.verify(modified_msg, signature, pk))
    
    def test_deterministic_signatures(self): # Determinism test
        # Test that signing the same message with the same private key produces the same signature (determinism)
        # This is because the nonce is derived from the private key and message, so it stays same.
        sk = self.ed25519_instance.generate_private_key()
        msg = Message(b"p79-assignment-2")

        signature1 = self.ed25519_instance.sign(msg, sk)
        signature2 = self.ed25519_instance.sign(msg, sk)

        # The two signatures should be identical
        self.assertEqual(signature1.signature_bytes, signature2.signature_bytes)
    


if __name__ == '__main__':
    unittest.main()