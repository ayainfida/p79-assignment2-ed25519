from enum import Enum
from os import urandom

from .point import Point
from hashlib import sha512
from .methods import double_and_add
from .defaults import BASE_X_SIGN, BASE_Y, q
from .primitives import LengthError, PrivateKey, PublicKey, Signature, Message
from .encoding import decode_little_endian, decode_scalar, encode_little_endian, point_compression, point_decompression

class ED25519ScalarMultAlgorithm(Enum):
    SCALAR_MULT = "scalar_mult"
    FAST_SCALAR_MULT = "fast_scalar_mult"

class ED25519:
    def __init__(self, algorithm: ED25519ScalarMultAlgorithm = ED25519ScalarMultAlgorithm.SCALAR_MULT):
        """
        Initialize the EDD25519 class with the specified algorithm.
        
        :param algorithm: The method to use for point addition and doubling (double_and_add or fast_scalar_mult).
        """
        self.algorithm = algorithm
        self.base_point = Point(y=BASE_Y, is_odd=BASE_X_SIGN)

    def scalar_mult(self, k: int, Pt: Point) -> Point:
        """
        Perform scalar multiplication on the given point using the specified algorithm.
        
        :param k: The scalar multiplier.
        :param Pt: The point to multiply.
        :return: The resulting point kP.
        """
        if self.algorithm == ED25519ScalarMultAlgorithm.SCALAR_MULT or self.algorithm == ED25519ScalarMultAlgorithm.FAST_SCALAR_MULT:
            return double_and_add(k, Pt)
        elif self.algorithm == ED25519ScalarMultAlgorithm.FAST_SCALAR_MULT:
            return double_and_add(k, Pt.to_extended_coordinates()).to_affine_coordinates()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
    @staticmethod
    def generate_private_key() -> PrivateKey:
        """
        Generate a new random private key.
        """
        sk = urandom(32)
        return PrivateKey(key_bytes=sk)

    def derive_public_key(self, sk: PrivateKey) -> PublicKey:
        """
        Derive the public key from the given private key.
        
        :param sk: The private key to derive the public key from.
        :return: The corresponding public key.
        """
        if not isinstance(sk, PrivateKey):
            raise TypeError("sk must be an instance of PrivateKey, given type: {}".format(type(sk)))
        
        if len(sk.key_bytes) != 32:
            raise LengthError(f"Private key must be 32 bytes long. Provided length: {len(sk.key_bytes)}")

        # Hash the private key to get a secret scalar and a nonce
        h = sha512(sk.key_bytes).digest()

        # The first 32 bytes of the hash are used to derive the secret scalar
        s_bytes = h[:32]
        secret_scalar = decode_scalar(s_bytes)

        # We compute the public key by performing scalar multiplication of the base point with the secret scalar
        # and then compressing the resulting point to get the public key bytes
        return PublicKey(point_compression(self.scalar_mult(secret_scalar, self.base_point)))
    
    def sign(self, message: Message, sk: PrivateKey) -> Signature:
        """
        Sign a message using the given private key.
        
        :param message: The message to sign.
        :param sk: The private key to use for signing.
        :return: The signature bytes.
        """
        if not isinstance(sk, PrivateKey):
            raise TypeError("sk must be an instance of PrivateKey, given type: {}".format(type(sk)))
        if not isinstance(message, Message):
            raise TypeError("message must be an instance of Message, given type: {}".format(type(message)))
        if len(sk.key_bytes) != 32:
            raise LengthError(f"Private key must be 32 bytes long. Provided length: {len(sk.key_bytes)}")

        # Hash the private key to get a secret scalar and a nonce
        h = sha512(sk.key_bytes).digest()

        # We split the hash into two parts: 
        # the first 32 bytes are used to derive the secret scalar, 
        # and the remaining 32 bytes are used as a prefix
        s_bytes = h[:32]
        prefix = h[32:]

        # Compute the public key from the secret scalar
        secret_scalar = decode_scalar(s_bytes)
        pk = self.derive_public_key(sk)

        r = sha512(prefix + message.message_bytes).digest()
        r_scalar = decode_little_endian(r) % q
        R = point_compression(self.scalar_mult(r_scalar, self.base_point))

        k = decode_little_endian(sha512(R + pk.key_bytes + message.message_bytes).digest()) % q

        t = encode_little_endian((r_scalar + k * secret_scalar) % q)

        signature = Signature(R + t)

        return signature
    
    def verify(self, message: Message, signature: Signature, pk: PublicKey) -> bool:
        """
        Verify a signature for a given message and public key.
        
        :param message: The message that the user received and wants to verify the signature for.
        :param signature: The signature received.
        :param pk: The public key of the sender who claimed to send this message.
        :return: True if the signature is valid, False otherwise.
        """
        if not isinstance(message, Message):
            raise TypeError("message must be an instance of Message, given type: {}".format(type(message)))
        if not isinstance(signature, Signature):
            raise TypeError("signature must be an instance of Signature, given type: {}".format(type(signature)))
        if not isinstance(pk, PublicKey):
            raise TypeError("pk must be an instance of PublicKey, given type: {}".format(type(pk)))
        
        if len(signature.signature_bytes) != 64:
            raise LengthError(f"Signature must be 64 bytes long. Provided length: {len(signature.signature_bytes)}")
        if len(pk.key_bytes) != 32:
            raise LengthError(f"Public key must be 32 bytes long. Provided length: {len(pk.key_bytes)}")
        
        R_bytes = signature.signature_bytes[:32]
        t_bytes = signature.signature_bytes[32:]

        # If t is not in the range [0, q), the signature is invalid (since t is supposed to be a scalar mod q) ~ Section 5.1.7. of RFC 8032
        if decode_little_endian(t_bytes) >= q:
            return False

        try:
            R = point_decompression(R_bytes)
            t = decode_little_endian(t_bytes) % q

            k = decode_little_endian(sha512(R_bytes + pk.key_bytes + message.message_bytes).digest()) % q

            pk = point_decompression(pk.key_bytes)

            lhs = self.scalar_mult(t, self.base_point)
            right_side = R + self.scalar_mult(k, pk)
        except ValueError:
            return False
        
        return lhs == right_side
    

if __name__ == "__main__":
    edd = ED25519(algorithm=ED25519Algorithm.FAST_SCALAR_MULT)
    msg = Message(b"")
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = edd.derive_public_key(PrivateKey(sk))
    print("Public Key:", pk.key_bytes.hex())
    sig = edd.sign(msg, PrivateKey(sk))
    print("Signature:", sig.signature_bytes.hex())
    is_valid = edd.verify(msg, sig, pk)
    print("Signature is valid:", is_valid)

    # msg1 = Message(bytes.fromhex("72")) 
    # sk1 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    # pk1 = edd.derive_public_key(PrivateKey(sk1))
    # print("Public Key:", pk1.key_bytes.hex())
    # sig1 = edd.sign(msg1, PrivateKey(sk1))
    # print("Signature:", sig1.signature_bytes.hex())
    # is_valid1 = edd.verify(msg1, sig1, pk1)
    # print("Signature is valid:", is_valid1)

    # msg2 = Message(bytes.fromhex("af82"))
    # print("Message:", msg2.message_bytes.hex())
    # sk2 = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    # pk2 = edd.derive_public_key(PrivateKey(sk2))
    # print("Public Key:", pk2.key_bytes.hex())
    # sig2 = edd.sign(msg2, PrivateKey(sk2))
    # print("Signature:", sig2.signature_bytes.hex())
    # is_valid2 = edd.verify(msg2, sig2, pk2)
    # print("Signature is valid:", is_valid2)

    # msg3 = Message(bytes.fromhex("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"))
    # print("Message:", msg3.message_bytes.hex())
    # sk3 = bytes.fromhex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5")
    # pk3 = edd.derive_public_key(PrivateKey(sk3))
    # print("Public Key:", pk3.key_bytes.hex())
    # sig3 = edd.sign(msg3, PrivateKey(sk3))
    # print("Signature:", sig3.signature_bytes.hex())
    # is_valid3 = edd.verify(msg3, sig3, pk3)
    # print("Signature is valid:", is_valid3)