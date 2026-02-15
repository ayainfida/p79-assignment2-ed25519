import unittest
import random
from ed25519 import Point
from ed25519.field import FieldElement
from ed25519.defaults import p
from ed25519.encoding import point_decompression, point_compression, decode_scalar, decode_little_endian

class TestEncoding(unittest.TestCase):    
    def test_point_decompression_mask_msb(self):
        # The highest bit of the last byte should be cleared as defined in RFC 8032 for x-coordinate decoding
        b = bytearray(32)
        b[-1] = 0x80  # Set the msb in the last byte to 1      
        decoded = point_decompression(bytes(b))
        self.assertEqual(decoded.y.value, 0)

    def test_compress_decompress_point(self):
        # Ensure that point compression followed by decompression returns the original point (round-trip property).

        # Values of y covering small, near p, and larger than p cases
        test_values = [0, 1, 128, 123456789, p-1, p, p+5, p+123456789, 2*p+42]

        for y in test_values:
            # x is automatically calculated from y and the sign, so we only need to specify y and the parity of x
            Pt = Point(y=FieldElement(y), is_odd=random.choice([True, False]))
            encoded = point_compression(Pt)
            decoded = point_decompression(encoded)
            # The decompressed point should have the same y-coordinate, x-coordinate, and the same parity of x as the original point
            self.assertEqual(Pt, decoded)
    
    def test_decode_scalar(self):
        # Test that decode_scalar correctly clamps (prune buffer) as per RFC 8032 and decodes the scalar
        
        # Example scalar before clamping
        original_scalar = bytearray(32)
        original_scalar[0] = 0xFF  # All bits set in first byte
        original_scalar[31] = 0xFF  # All bits set in last byte

        decoded_scalar = decode_scalar(bytes(original_scalar))

        # Check clamping
        self.assertEqual(decoded_scalar & 0b00000111, 0)  # 3 LSBs cleared
        self.assertEqual(decoded_scalar & (1 << 255), 0)  # MSB cleared
        self.assertEqual(decoded_scalar & (1 << 254), 1 << 254)  # Second MSB set

        # No effect on values that are already clamped, so decoding a clamped scalar should return the same integer
        test_scalar = bytearray(32)
        test_scalar[0] = 0xF8
        test_scalar[31] = 0x40
        self.assertEqual(decode_scalar(bytes(test_scalar)), decode_little_endian(bytes(test_scalar)))

if __name__ == '__main__':
    unittest.main()