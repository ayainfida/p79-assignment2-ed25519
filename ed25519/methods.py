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
    assert k >= 1, "k must be a positive integer"

    if k == 1:
        return Pt
    elif k & 1 == 0: # k is even: we double the point
        return double_and_add(k // 2, Pt).double()
    else: # k is odd: we first double and then add the original point
        return double_and_add((k - 1) // 2, Pt).double() + Pt
    
if __name__ == "__main__":
    from .encoding import decode_little_endian, decode_scalar, encode_coordinate
    sk = bytes.fromhex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5")
    from hashlib import sha512
    hash = sha512(sk).hexdigest()
    first_half = hash[:64]
    clamped_first_half = decode_scalar(bytes.fromhex(first_half))
    # print(clamped_first_half)
    # print(decode_little_endian(sk))

    from .defaults import BASE_X_SIGN, BASE_Y



    x = double_and_add(clamped_first_half, Point(BASE_Y, BASE_X_SIGN))
    print(hex(int.from_bytes(encode_coordinate(x), byteorder='little')))