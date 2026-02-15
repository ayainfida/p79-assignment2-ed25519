import unittest
from ed25519 import ExtendedPoint, Point
from ed25519.defaults import BASE_X_SIGN, BASE_Y

"""
Unit tests for group law operations on the Edwards curver.
These are not exhaustive but cover basic properties, necessary for correctness.
"""

class TestGroupLaw(unittest.TestCase):
    def setUp(self):
        self.Pt = Point(y=BASE_Y, is_odd=BASE_X_SIGN)
        self.ExtendedPt = self.Pt.to_extended_coordinates()

    def test_base_point_is_valid(self):
        # Ensure the base point lies on the curve
        self.assertTrue(self.Pt.is_valid())

    def test_identity(self):
        # Test that adding the identity point returns the original point
        self.assertEqual(self.Pt + Point.identity(), self.Pt)
        self.assertEqual(Point.identity() + self.Pt, self.Pt)
        
        # Same for the extended point
        self.assertEqual(self.ExtendedPt + ExtendedPoint.identity(), self.ExtendedPt)
        self.assertEqual(ExtendedPoint.identity() + self.ExtendedPt, self.ExtendedPt)

    def test_result_is_on_curve(self):
        # Ensure the result of doubling is still on the curve
        Q = self.Pt.double() # Note: the constructor ensures validity itself so no need to explicitly call `is_valid()`
        self.assertTrue(Q.is_valid())

        P = self.Pt + self.Pt + self.Pt
        self.assertTrue(P.is_valid())

        # Same for the extended point
        Q_ext = self.ExtendedPt.double()
        self.assertTrue(Q_ext.to_affine_coordinates().is_valid())

        P_ext = self.ExtendedPt + self.ExtendedPt + self.ExtendedPt
        self.assertTrue(P_ext.to_affine_coordinates().is_valid())

if __name__ == "__main__":
    unittest.main()