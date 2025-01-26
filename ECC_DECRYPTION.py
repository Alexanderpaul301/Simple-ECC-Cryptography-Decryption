from ecdsa.ellipticcurve import Point # Import the ecdsa library to make this code work
from ecdsa.numbertheory import inverse_mod

# Definition of the elliptic curve
p = 31  # Modulo
A = 2  # X coefficient
B = 7  # constant term


Px, Py = 2, 9 # Coordinates of the base point P
P = Point(None, Px, Py)
m = 8  # Private key

# function to perform point addition on an elliptic curve
def point_addition(P1, P2, p):
    if P1 == P2:  # Doubling point case
        s = (3 * P1.x()**2 + A) * inverse_mod(2 * P1.y(), p) % p
    else:  # Scalar addition of two points
        s = (P2.y() - P1.y()) * inverse_mod(P2.x() - P1.x(), p) % p

    x3 = (s**2 - P1.x() - P2.x()) % p
    y3 = (s * (P1.x() - x3) - P1.y()) % p

    return Point(None, x3, y3)

# Function to perform scalar multiplication kP = P + P + ... + P
def scalar_multiplication(k, P, p):
    result = None
    addend = P

    while k:
        if k & 1:
            result = point_addition(result, addend, p) if result else addend
        addend = point_addition(addend, addend, p)
        k >>= 1

    return result


# Compute the public key Q = m * P
Q = scalar_multiplication(m, P, p)
print(f"Q = ({Q.x()}, {Q.y()})")

# Decrypt the ciphertexts
ciphertexts = [(18, 1, 21), (3, 1, 18), (17, 0, 19), (28, 0, 8)]
plaintexts = []

for C1x, C1y, C2 in ciphertexts:
    C1 = Point(None, C1x, C1y)
    S = scalar_multiplication(m, C1, p)  # Calculation of S = m * C1
    plaintext = (C2 - S.x()) % p  # Plaintext : M = C2 - S.x mod p
    plaintexts.append(plaintext)

print("Decrypted messages :", plaintexts)
