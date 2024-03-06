from utils.MessengerExceptions import Base85Exception

BASE_85_ALPHABET = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu"


def intToBase85(paramBase10: int, nBytes=None) -> str:
    """
    Convert an int to base 85
    :param paramBase10: int to convert
    :param nBytes: number of bytes to convert
    :return: base85 encoded int
    """

    digits = paramBase10.bit_length() if nBytes is None else nBytes * 8  # Number of bits in number

    # Round up to closest multiple of 8
    if digits % 8 != 0:
        digits += 8 - (digits % 8)

    # Convert base 10 to bytes
    byteStream = list( paramBase10.to_bytes(digits // 8, byteorder="big", signed=False) )

    # Make sure the byte stream is a multiple of 4
    if len(byteStream) % 4 != 0:
        raise Base85Exception(None, Base85Exception.INVALID_NUMBER_OF_CHARACTERS_DECODE)

    # Split into list of 4 bytes i.e 8bytes -> [4bytes, 4bytes]
    byte4Split = [[val := val + (byte << (byteIndex * 8)) if byteIndex > 0 else (val := byte)
                  for byteIndex, byte in enumerate(reversed(a))][-1]
                  for a in [byteStream[index*4:(index+1)*4] for index in range(len(byteStream) // 4)]]

    # Base 85 builder using recursion and buckets using the 4 byte splits
    BASE_85_BUILDER = lambda value, exp: BASE_85_ALPHABET[value // pow(len(BASE_85_ALPHABET), exp)] + BASE_85_BUILDER(
        value % pow(len(BASE_85_ALPHABET), exp), exp - 1) if exp else BASE_85_ALPHABET[value]

    # Join the base85 using the base 85 builder for each 4byte split
    return "".join([BASE_85_BUILDER(val, 4) for val in byte4Split])


def base85ToInt(paramBase85: str) -> int:
    """
    Convert base85 to int
    :param paramBase85: Base 85 to convert
    :return: int result
    """

    # Check that the base85 is a multiple of 5 bytes
    if len(paramBase85) % 5 != 0:
        raise Base85Exception(None, Base85Exception.INVALID_NUMBER_OF_CHARACTERS_ENCODE)

    # Check that all characters are in the base85 alphabet
    if any([True for s in paramBase85 if s not in BASE_85_ALPHABET]):
        raise Base85Exception(None, Base85Exception.INVALID_CHARACTER)

    # Split into groups of 5 characters
    char5split = [paramBase85[index * 5:index * 5 + 5] for index in range(len(paramBase85) // 5)]
    decimals = [0] * (len(paramBase85) // 5)  # Decimal list, replace 0 later with the correct number

    # Iterate over index, charString for each group of 5 characters
    for charStringIndex, charString in enumerate(char5split):
        for exp in range(5):  # Calculate each exponent and find the resulting base 85
            decimals[charStringIndex] += BASE_85_ALPHABET.index(charString[exp]) * len(BASE_85_ALPHABET) ** (4 - exp)

    # Join the converted binary in decimals and return as an int
    valueBase2 = "".join([bin(d)[2:].zfill(32) for d in decimals])
    return int(valueBase2, 2)