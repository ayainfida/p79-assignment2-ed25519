from .point import Point
from .field import FieldElement

def decode_little_endian(b: bytes) -> int:
    """
    Decode a little-endian byte sequence to an integer.
    """
    return sum((b[i] << (8 * i)) for i in range(len(b)))

def encode_little_endian(x: int, length: int = 32) -> bytes:
    """
    Encode an integer to a little-endian byte sequence of the specified length.
    """
    b = bytearray(length)
    for i in range(length):
        b[i] = (x >> (8 * i)) & 0xFF
    return bytes(b)

def point_decompression(b: bytes) -> Point:
    """
    Decompress a 32-byte little-endian byte sequence to a Point on the Ed25519 curve.
    """
    assert len(b) == 32, "Input must be 32 bytes long."

    # Extract the least significant bit of the last byte to determine the sign of x
    lsb = (b[-1] >> 7) & 1
    
    # Clear the highest bit of the last byte
    b = b[:-1] + bytes([b[-1] & 0x7F])

    return Point(FieldElement(decode_little_endian(b)), lsb)

def point_compression(Pt: Point) -> bytes:
    """
    Compress a Point to a 32-byte little-endian byte sequence.
    """    
    b = bytearray(encode_little_endian(Pt.y.value))
    # Set the highest bit of the last byte to the lsb of x
    b[31] &= 0x7F
    b[31] |= (Pt.x.value & 1) << 7
    
    return bytes(b)

def clamp_scalar(k: bytes) -> bytes:
    """
    Clamp a 32-byte scalar as per RFC 8032 (aka. pruning the buffer for the secret scalar):
    - Set 3 least-significant bits to 0
    - Set the most-significant bit to 0
    - Set the second most-significant bit to 1
    """
    assert len(k) == 32, "Input must be 32 bytes long."

    k_arr = bytearray(k)
    k_arr[0] &= 248          
    k_arr[31] &= 127        
    k_arr[31] |= 64         
    
    return bytes(k_arr)

def decode_scalar(k: bytes) -> int:
    """
    Decode a 32-byte little-endian byte sequence to a clamped scalar integer.
    """
    assert len(k) == 32, "Input must be 32 bytes long."
    
    k_clamped = clamp_scalar(k)
    return decode_little_endian(k_clamped)
