from dataclasses import dataclass

from .field import FieldElement

from .defaults import d, p


@dataclass
class Point:
    def __init__(self, y: FieldElement, is_odd: bool, x: FieldElement | None = None):
        """
        Initialize a point on the Edwards curve defined by the equation:
        -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)
        
        :param x: The x-coordinate of the point (optional).
        :param y: The y-coordinate of the point.
        """
        assert isinstance(y, FieldElement), "y must be a FieldElement"

        self.y = y
        self.is_odd = is_odd

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
        if int(self.is_odd) != (x.value & 1):
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

        is_odd = int(x3.value & 1)

        return Point(y3, is_odd, x3)
    
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


if __name__ == "__main__":
    x = Point(y=FieldElement(1), is_odd=1)
    print((x + x).x, (x + x).y)