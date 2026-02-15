
from dataclasses import dataclass

@dataclass(frozen=True)
class Key:
    """
    A base class for representing keys in the Ed25519 signature scheme.
    """
    key_bytes: bytes

    def __post_init__(self):
        if len(self.key_bytes) != 32:
            raise ValueError(f"{type(self).__name__} must be 32 bytes long. Provided length: {len(self.key_bytes)}")


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

    def __post_init__(self):
        if len(self.signature_bytes) != 64:
            raise ValueError(f"Signature must be 64 bytes long. Provided length: {len(self.signature_bytes)}")
        
@dataclass(frozen=True)
class Message:
    """
    A class representing a message in the Ed25519 signature scheme.
    """
    message_bytes: bytes