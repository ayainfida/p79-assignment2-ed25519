from enum import Enum
from os import urandom
from .point import Point
from hashlib import sha512
from .field import Field_q
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
        self.base_point = Point(y=BASE_Y, sign=BASE_X_SIGN)

    def scalar_mult(self, k: int, Pt: Point) -> Point:
        """
        Perform scalar multiplication on the given point using the specified algorithm.
        
        :param k: The scalar multiplier.
        :param Pt: The point to multiply.
        :return: The resulting point kP.
        """
        if self.algorithm == ED25519ScalarMultAlgorithm.SCALAR_MULT:
            result = double_and_add(k, Pt) # incase of scalar_mult, we can directly use the Point type
        elif self.algorithm == ED25519ScalarMultAlgorithm.FAST_SCALAR_MULT:
            result = double_and_add(k, Pt.to_extended_coordinates()) # in case of fast_scalar_mult, we need to convert the point to ExtendedPoint before performing the scalar multiplication
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        # For the fast_scalar_mult algorithm, the result will be in extended coordinates, so we convert it back to Point
        if not isinstance(result, Point):
            return result.to_affine_coordinates()
        return result
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
        # Type and length validation at API boundary 
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
    
    def sign(self, msg: Message, sk: PrivateKey) -> Signature:
        """
        Sign a message using the given private key.
        
        :param msg: The message to sign.
        :param sk: The private key to use for signing.
        :return: The signature bytes.
        """
        # Type and length validation at API boundary 
        if not isinstance(sk, PrivateKey):
            raise TypeError("sk must be an instance of PrivateKey, given type: {}".format(type(sk)))
        if not isinstance(msg, Message):
            raise TypeError("msg must be an instance of Message, given type: {}".format(type(msg)))
        if len(sk.key_bytes) != 32:
            raise LengthError(f"Private key must be 32 bytes long. Provided length: {len(sk.key_bytes)}")

        # Hash the private key to get a secret scalar and a deterministic nonce
        h = sha512(sk.key_bytes).digest()

        # We split the hash into two parts: 
        # the first 32 bytes are used to derive the secret scalar, 
        # and the remaining 32 bytes are used as a prefix
        s_bytes = h[:32]
        prefix = h[32:]

        # Compute the public key from the secret scalar
        secret_scalar = Field_q(decode_scalar(s_bytes))
        pk = self.derive_public_key(sk)

        # Nonce generation: r = H(prefix || msg) 
        # This ensures that the nonce is deterministic and unique for each message, preventing nonce reuse vulnerabilities.
        r = sha512(prefix + msg.message_bytes).digest()
        r_scalar = Field_q(decode_little_endian(r))
        # Compute the point R = r * base_point and compress it to get the first part of the signature
        R = point_compression(self.scalar_mult(r_scalar.value, self.base_point))

        # Compute the scalar k = H(R || pk || msg) which will be used in the signature generation
        k = Field_q(decode_little_endian(sha512(R + pk.key_bytes + msg.message_bytes).digest()))

        # Compute the second part of the signature t = (r + k * secret_scalar)
        t = encode_little_endian((r_scalar + k * secret_scalar).value)

        signature = Signature(R + t)

        return signature
    
    def verify(self, msg: Message, sig: Signature, pk: PublicKey) -> bool:
        """
        Verify a signature for a given message and public key.
        
        :param msg: The message that the user received and wants to verify the signature for.
        :param sig: The signature received.
        :param pk: The public key of the sender who claimed to send this message.
        :return: True if the signature is valid, False otherwise.
        """
        # Type and length validation at API boundary 
        if not isinstance(msg, Message):
            raise TypeError("msg must be an instance of Message, given type: {}".format(type(msg)))
        if not isinstance(sig, Signature):
            raise TypeError("sig must be an instance of Signature, given type: {}".format(type(sig)))
        if not isinstance(pk, PublicKey):
            raise TypeError("pk must be an instance of PublicKey, given type: {}".format(type(pk)))
        
        if len(sig.signature_bytes) != 64:
            raise LengthError(f"Signature must be 64 bytes long. Provided length: {len(sig.signature_bytes)}")
        if len(pk.key_bytes) != 32:
            raise LengthError(f"Public key must be 32 bytes long. Provided length: {len(pk.key_bytes)}")
        
        # Split signature into R (encoded point) and S (scalar)
        R_bytes = sig.signature_bytes[:32]
        t_bytes = sig.signature_bytes[32:]

        # If t is not in the range [0, q), the signature is invalid (since t is supposed to be a scalar mod q) ~ Section 5.1.7. of RFC 8032
        if decode_little_endian(t_bytes) >= q:
            return False

        try:
            # Decompress R and public key point
            R = point_decompression(R_bytes)
            pk_point = point_decompression(pk.key_bytes)

            # Decode t and k from the signature and the message
            t = Field_q(decode_little_endian(t_bytes))
            # Recompute the scalar k = H(R || pk || msg) 
            k = Field_q(decode_little_endian(sha512(R_bytes + pk.key_bytes + msg.message_bytes).digest()))

            # Verify the signature by checking if the equation holds: t * base_point == R + k * pk_point
            lhs = self.scalar_mult(t.value, self.base_point)
            right_side = R + self.scalar_mult(k.value, pk_point)

        except ValueError:
            return False
        
        return lhs == right_side