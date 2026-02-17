
from dataclasses import dataclass

"""
This module defines the basic data structures for keys,
signatures, and messages used in the Ed25519 signature scheme.
"""

@dataclass(frozen=True)
class Key:
    """
    A base class for representing keys in the Ed25519 signature scheme.
    """
    key_bytes: bytes

class PrivateKey(Key):
    """
    A class representing a private key in the Ed25519 signature scheme.
    """
    pass


class PublicKey(Key):
    """
    A class representing a public key in the Ed25519 signature scheme.
    """
    pass

@dataclass(frozen=True)
class Signature:
    """
    A class representing a signature in the Ed25519 signature scheme.
    """
    signature_bytes: bytes
        
@dataclass(frozen=True)
class Message:
    """
    A class representing a message in the Ed25519 signature scheme.
    """
    message_bytes: bytes

# Exception defined for handling length errors in keys and signatures
class LengthError(ValueError):
    pass