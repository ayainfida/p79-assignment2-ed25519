from .field import FieldElement

# Setting default curve parameters for Ed25519
# equation: -x^2 + y^2 = 1 + d*x^2*y^2 over the field defined by prime p

# Prime number defining the field
p = 2**255 - 19

# Field q 
q = 2**252 + 27742317777372353535851937790883648493

# Curve parameter d
d = - (FieldElement(121665) / FieldElement(121666))

# Base point coordinates on the edwards curve 25519 (from wikipedia https://en.wikipedia.org/wiki/EdDSA)
BASE_Y = FieldElement(4) / FieldElement(5)
BASE_X_SIGN = 0 # Sign of the x-coordinate of the base point (0 for positive, 1 for negative)
