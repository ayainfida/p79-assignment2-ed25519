from dataclasses import dataclass

from .field import FieldElement

from .defaults import d


@dataclass
class Point:
    def __init__(self, y: FieldElement, sign: int, x: FieldElement | None = None):
        """
        Initialize a point on the Edwards curve defined by the equation:
        -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)
        
        :param x: The x-coordinate of the point (optional).
        :param y: The y-coordinate of the point.
        :param sign: The sign of the x-coordinate (0 for positive, 1 for negative).
        """
        assert isinstance(y, FieldElement), "y must be a FieldElement"

        self.y = y
        self.sign = sign

        if x is not None:
            assert isinstance(x, FieldElement), "x must be a FieldElement"
            self.x = x
            if not self.is_valid():
                raise ValueError("The provided point is not a valid point on the curve.")
        else:
            x = self.calculate_x()
            if x is None:
                raise ValueError("The provided y-coordinate does not correspond to a valid point on the curve.")
            self.x = x
        
    def is_valid(self) -> bool:
        """
        Check if the point lies on the curve defined by the equation:
        -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)
        """
        x_square = self.x.square()
        y_square = self.y.square()

        lhs = y_square - x_square
        rhs = FieldElement(1) + d * x_square * y_square

        return lhs == rhs
    
    def calculate_x(self) -> FieldElement | None:
        """
        Given the y-coordinate and the sign, calculate the corresponding x-coordinate on the curve.
        """
        y_square = self.y.square()
        one = FieldElement(1)

        # numerator = y^2 - 1
        numerator = y_square - one
        # denominator = d*y^2 + 1
        denominator = d * y_square + one

        x_square = numerator / denominator

        # Compute x
        try:
            x = x_square.sqrt()
        except ValueError:
            return None
        
        # Check if x has the correct parity
        if self.sign != (x.value & 1):
            return -x
        else:
            return x
        
    def __add__(self, other: "Point") -> "Point":
        """
        Add two points on the Edwards curve.
        """
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        # Using the addition formulas for Edwards curves
        # x3, y3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2), (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2

        x3 = (x1 * y2 + x2 * y1) / (FieldElement(1) + d * x1 * x2 * y1 * y2)
        y3 = (y1 * y2 + x1 * x2) / (FieldElement(1) - d * x1 * x2 * y1 * y2)

        sign = int(x3.value & 1)

        return Point(y3, sign, x3)
    
    def double(self) -> "Point":
        """
        Double a point on the Edwards curve.
        """
        return self + self
    
    def __eq__(self, other: object) -> bool:
        """
        Check if two points are equal.
        """
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y
    
    def to_extended_coordinates(self) -> "ExtendedPoint":
        """
        Convert the point to extended homogeneous coordinates (X:Y:Z:T) where x = X/Z, y = Y/Z, and T = XY/Z.
        """
        X = self.x
        Y = self.y
        Z = FieldElement(1)
        T = X * Y
        return ExtendedPoint(X, Y, Z, T)
    
    @staticmethod
    def identity() -> "Point":
        """
        Return the identity point of the group, which is (0, 1) in affine coordinates.
        """
        return Point(FieldElement(1), 0, FieldElement(0))


@dataclass
class ExtendedPoint:
    """
    A class that represents points in extended homogeneous coordinates (X:Y:Z:T) where x = X/Z, y = Y/Z, and T = XY/Z.
    This is used for faster point addition and doubling.
    """
    X: FieldElement
    Y: FieldElement
    Z: FieldElement
    T: FieldElement

    def to_affine_coordinates(self) -> Point:
        """
        Convert the point from extended homogeneous coordinates back to affine coordinates (x, y).
        """
        x = self.X / self.Z
        y = self.Y / self.Z
        sign = int(x.value & 1)
        return Point(y, sign, x)
    
    def __add__(self, other: "ExtendedPoint") -> "ExtendedPoint":
        """
        Add two points using the extended homogeneous coordinates for faster addition.
        Section 3.1 from Twisted Edwards Curves Revisited (Hisil et al., 2008).
        """
        # Point 1 
        X1, Y1, Z1, T1 = self.X, self.Y, self.Z, self.T
        # Point 2
        X2, Y2, Z2, T2 = other.X, other.Y, other.Z, other.T

        # Compute the sum using extended homogeneous coordinates formulas
        # For twisted Edwards curve with a = -1: -x^2 + y^2 = 1 + d*x^2*y^2
        A = X1 * X2
        B = Y1 * Y2
        C = d * T1 * T2
        D = Z1 * Z2
        E = (X1 + Y1) * (X2 + Y2) - A - B
        F = D - C
        G = D + C
        H = B + A  # For a = -1: H = B - a*A = B - (-1)*A = B + A
        X3 = E * F
        Y3 = G * H
        Z3 = F * G
        T3 = E * H

        return ExtendedPoint(X3, Y3, Z3, T3)

    def double(self) -> "ExtendedPoint":
        """
        Double a point on the Edwards curve.
        """
        return self + self
    
    def __eq__(self, other: object) -> bool:
        """
        Check if two points are equal.
        """
        if not isinstance(other, ExtendedPoint):
            return NotImplemented
        return self.X == other.X and self.Y == other.Y and self.Z == other.Z and self.T == other.T
    
    @staticmethod
    def identity() -> "ExtendedPoint":
        """
        Return the identity point of the group in extended homogeneous coordinates, which is (0:1:1:0).
        """
        return ExtendedPoint(FieldElement(0), FieldElement(1), FieldElement(1), FieldElement(0))


if __name__ == "__main__":
    x = Point(y=FieldElement(1), sign=1)
    print((x + x).x, (x + x).y)