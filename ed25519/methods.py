from .point import ExtendedPoint, Point

def double_and_add(k: int, Pt: Point | ExtendedPoint) -> Point | ExtendedPoint:
    """
    Perform scalar multiplication using the double-and-add method.
    
    Args:
        k (int): The scalar multiplier.
        Pt (Point | ExtendedPoint): The point to multiply.
    Returns: 
        (Point | ExtendedPoint): The resulting point kP.
    """
    assert isinstance(Pt, Point) or isinstance(Pt, ExtendedPoint), "Pt must be a Point or ExtendedPoint instance."
    assert k >= 0, f"k must be a positive integer {k} is not valid."

    if k == 0:
        return Pt.identity()
    elif k == 1:
        return Pt
    elif k & 1 == 0: # k is even: we double the point
        return double_and_add(k // 2, Pt).double()
    else: # k is odd: we first double and then add the original point
    # Added type ignore to suppress mypy error about adding Point and ExtendedPoint. 
    # Since this is recursive, the type will always be correct at runtime, and same as what we passed initially.)
        return double_and_add((k - 1) // 2, Pt).double() + Pt # type: ignore