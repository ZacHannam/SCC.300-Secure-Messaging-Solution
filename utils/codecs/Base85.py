BASE_85_ALPHABET = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu"


def intToBase85(paramBase10: int, nBytes=None) -> str:

    digits = paramBase10.bit_length() if nBytes is None else nBytes * 8

    if digits % 8 != 0:
        digits += 8 - (digits % 8)

    byteStream = list( paramBase10.to_bytes(digits // 8, byteorder="big", signed=False) )

    if len(byteStream) % 4 != 0:
        raise ValueError("Number of bytes must be a multiple of 4")

    byte4Split = [[val := val + (byte << (byteIndex * 8)) if byteIndex > 0 else (val := byte)
                  for byteIndex, byte in enumerate(reversed(a))][-1]
                  for a in [byteStream[index*4:(index+1)*4] for index in range(len(byteStream) // 4)]]

    BASE_85_BUILDER = lambda val, exp: BASE_85_ALPHABET[val // pow(len(BASE_85_ALPHABET), exp)] + BASE_85_BUILDER(
        val % pow(len(BASE_85_ALPHABET), exp), exp - 1) if exp else BASE_85_ALPHABET[val]

    return "".join([BASE_85_BUILDER(val, 4) for val in byte4Split])


def base85ToInt(paramBase85: str) -> int:

    if len(paramBase85) % 5 != 0:
        raise ValueError("Number of characters must be a multiple of 5")

    if any([True for s in paramBase85 if s not in BASE_85_ALPHABET]):
        raise KeyError("Character is not in the base85 alphabet")

    char5split = [paramBase85[index * 5:index * 5 + 5] for index in range(len(paramBase85) // 5)]
    decimals = [0] * (len(paramBase85) // 5)

    for charStringIndex, charString in enumerate(char5split):
        for exp in range(5):
            decimals[charStringIndex] += BASE_85_ALPHABET.index(charString[exp]) * len(BASE_85_ALPHABET) ** (4 - exp)

    valueBase2 = "".join([bin(d)[2:].zfill(32) for d in decimals])
    return int(valueBase2, 2)