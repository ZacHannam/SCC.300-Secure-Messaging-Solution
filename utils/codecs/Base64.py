from utils.BinarySequencer import getBinFromSequence

BASE_64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789- "


def base64ToInt(paramBase64: str) -> int:

    if not all([char in BASE_64_ALPHABET for char in paramBase64]):
        raise ValueError("Illegal character encountered during conversion")

    base64bin = getBinFromSequence([BASE_64_ALPHABET.index(char) for char in paramBase64], 6)

    return base64bin.getResult()


def intToBase64(paramInt: int) -> str:

    characters = ""
    base64Int = paramInt
    while base64Int > 0:
        characters += BASE_64_ALPHABET[base64Int & 0x3F]  # 6 bits
        base64Int = base64Int >> 6

    return characters[::-1]
