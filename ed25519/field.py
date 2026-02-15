from dataclasses import dataclass
from typing import ClassVar, Self

@dataclass(frozen=True)
class ModInt:
    """
    A class that represents integers modulo a prime p i.e. x mod p.
    """
    value: int
    p: int

    def __post_init__(self):
        object.__setattr__(self, "value", self.value % self.p)

    def __is_field_element(self, other: object) -> None:
        # Checks if the other object is a ModInt and
        # if it belongs to the same field (i.e., has the same modulus)
        if not isinstance(other, ModInt):
            raise TypeError("Elements must be ModInts.")
        if self.p != other.p:
            raise ValueError("Elements must belong to the same field.")
    
    def __add__(self, other: Self) -> Self:
        """
        Add two field elements.
        """
        self.__is_field_element(other) 
        return type(self)(self.value + other.value, self.p)
    
    def __sub__(self, other: Self) -> Self:
        """
        Subtract two field elements.
        """
        self.__is_field_element(other)
        return type(self)(self.value - other.value, self.p)
    
    def __mul__(self, other: Self) -> Self:
        """
        Multiply two field elements.
        """
        self.__is_field_element(other)
        return type(self)(self.value * other.value, self.p)
    
    def inv(self) -> Self:
        """
        Compute the multiplicative inverse of a field element
        by using Fermat's little theorem:
        a^(p-1) = a.a^(p-2) ≡ 1 (mod p) 
        """
        if self.value == 0:
            raise ValueError("Cannot compute inverse of zero.")
        return type(self)(pow(self.value, self.p - 2, self.p), self.p)
    
    def __truediv__(self, other: Self) -> Self:
        """
        Divide two field elements.
        """
        self.__is_field_element(other)
        return type(self)(self.value * other.inv().value, self.p)
    
    def square(self) -> Self:
        """
        Square a field element.
        """
        return self * self
    
    def __eq__(self, other: object) -> bool:
        """
        Check if two field elements are equal.
        """
        if not isinstance(other, type(self)):
            return False
        return self.value == other.value
    
    def __neg__(self) -> Self:
        """
        Negate a field element.
        """
        return type(self)(-self.value, self.p)

# These classes inherits from ModInt which supports basic field operations.
@dataclass(frozen=True)    
class FieldElement(ModInt):
    """
    A class that represents an element of the finite field defined by the prime p used in Ed25519.
    """
    p: ClassVar[int] = 2**255 - 19

    def __init__(self, value: int, p: int = p):
        if p is None:
            p = self.p
        super().__init__(value, p)

    def sqrt(self) -> "FieldElement":
        """
        Compute the square root of a field element using the algorithm stated in Slide 116 (defined in RFC 8032).
        """
        assert self.p % 8 == 5, "The prime p must satisfy p ≡ 5 (mod 8) for this square root algorithm to work."

        if self.value == 0:
            return self
        
        # Compute (p + 3) // 8 once to avoid redundant calculations
        p38 = (self.p + 3) // 8
        
        candidate_root_1 = FieldElement(pow(self.value, p38, self.p))
        if candidate_root_1.square() == self:
            return candidate_root_1
        
        # Compute (p - 1) // 4 
        p14 = (self.p - 1) // 4
        sqrt_neg_one = FieldElement(pow(2, p14, self.p))
        
        candidate_root_2 = candidate_root_1 * sqrt_neg_one

        if candidate_root_1.square() == -self:
            return candidate_root_2
        
        raise ValueError("No square root exists for the given element in the field.")
    
@dataclass(frozen=True)
class Field_q(ModInt):
    """
    A class that represents an element of the finite field defined by the prime q used in Ed25519.
    """
    p: ClassVar[int] = 2**252 + 27742317777372353535851937790883648493
    
if __name__ == "__main__":
    # Example usage
    p = 2**255 - 19
    a = FieldElement(10)
    b = FieldElement(20)
    
    print("a + b =", (a + b).value)
    print("a - b =", (a - b).value)
    print("a * b =", (a * b).value)
    print("a / b =", (a / b).value)

    p1 = 101
    n = 1030

    print("p1 mod 8 =", p1 % 8)
    print((p+3) //8)
