from functools import lru_cache
import random
from enum import Enum, auto
import math
from typing import Any

from utils.MessengerExceptions import BinarySequencerException


class ArbitraryValue(Enum):
    """
    Arbitrary values that can be used in place of int and bytes
    """
    RANDOMISE = auto()  # Randomise when used in
    DYNAMIC = auto()    # Makes a dynamic byte


class Bin:
    def __init__(self, paramDimensions: list, population=0):
        """
        Binary sequencer that is used to convert data to a very simple and organised structure
        :param paramDimensions:
        :param population:
        """
        # Check that it has valid dimensions
        if not all([isinstance(dimension, tuple) and len(dimension) == 2 or len(dimension) == 3
                    for dimension in paramDimensions]):
            raise BinarySequencerException(None, BinarySequencerException.INVALID_DIMENSIONS)

        # If the population is in bytes convert to int
        if isinstance(population, bytes):
            population = int.from_bytes(population, byteorder="big")

        # IF the population is not now in int then it has an invalid form
        if not isinstance(population, int):
            raise BinarySequencerException(None, BinarySequencerException.INVALID_POPULATION_TYPE)

        # Fill out the pre set values in the dimensions
        setValues = []
        for index, dimension in enumerate(paramDimensions):
            if len(dimension) == 2:
                continue

            setValues.append((dimension[0], dimension[2]))
            paramDimensions[index] = dimension[0], dimension[1]

        # Set the dimensions now the pre-set values have been removed
        self.__dimensions = paramDimensions
        self.__dimension_values: list = [0] * self.getNumberOfBins()  # Dimensions values

        # Iterate through the dimensions and set values to set pre-set values
        for dimension, value in setValues:
            self.setAttribute(dimension, value)

        # Populate the population value
        if population != 0:
            self.populate(population)

    """
            Dimension Methods
    """

    def getDimensionValues(self) -> list:
        """
        Get the values for the dimensions
        :return: list of dimension's values
        """
        return self.__dimension_values

    @lru_cache
    def getDimensions(self) -> list[tuple]:
        """
        Get the dimensions for the bin
        :return: list of dimensions
        """
        return self.__dimensions

    """
            General Bin Methods
    """

    @lru_cache
    def getNumberOfBins(self) -> int:
        """
        Get the total number of dimensions
        :return: number of dimensions (int)
        """
        return len(self.__dimensions)

    def getBinSize(self) -> int:
        """
        Get the total number of bits used for the bin
        :return: bin size bits (int)
        """
        total = 0
        for attribute, attribute_size in self.getDimensions():

            # If the attribute size is dynamic then add the total bits that would be necessary to fulfill it
            if attribute_size == ArbitraryValue.DYNAMIC:
                attributeValue = self.getAttribute(attribute)
                if attributeValue == 0:
                    total += 8
                    continue

                size = int(math.ceil(math.log(attributeValue, 2)))
                logSize = int(math.ceil(math.log(size, 2)))
                total += size + logSize + int(math.ceil(size / 8)) + 1

                continue

            total += attribute_size

        return total

    def getBinSizeBytes(self) -> int:
        """
        Get the bin size in bytes
        :return: convert bits to bytes (/8)
        """
        return math.ceil(self.getBinSize() / 8)

    def xor(self, paramInt: int) -> None:
        """
        Xor the bin with the paramInt and re populate
        :param paramInt: what to xor the bin with
        :return: None
        """
        if self.getNumberOfDynamicBins():
            raise BinarySequencerException(None, BinarySequencerException.CANNOT_XOR_DYNAMIC_BIN)

        # Re populate using the xor result value
        self.populate(self.getResult() ^ paramInt)

    """
            Results And Populate
    """

    @lru_cache
    def getBinaryLength(self, paramInt: int) -> int:
        """
        Get the binary length of an int
        :param paramInt: the int to get the length of
        :return: value length in binary
        """
        if paramInt == 0:
            return 0

        return int(math.ceil(math.log(paramInt, 2)))

    @lru_cache
    def getNumberOfDynamicBins(self) -> int:
        """
        Get the number of dynamic bins
        :return: Number of dynamic bins
        """
        return sum([binSize == ArbitraryValue.DYNAMIC for _, binSize in self.getDimensions()])

    def getResult(self) -> int:
        """
        Get the result of the bin (int) is the binary value
        :return: the int version of the binary value
        """
        total = 0
        for (attribute, attribute_size), value in zip(self.getDimensions(), self.getDimensionValues()):
            # Check if the attribute is dynamic
            if attribute_size is not ArbitraryValue.DYNAMIC:
                total = total << attribute_size
                total += value
                continue

            # Push 17 across
            if value == 0:
                total = 0x100 << self.getBinaryLength(total) | total
                continue

            valueSizeBits = self.getBinaryLength(value)
            logValueSizeBits = self.getBinaryLength(valueSizeBits)

            prefix = 0
            for t in range(int(math.ceil(logValueSizeBits / 7))):
                prefix += (0x80 | ((valueSizeBits >> (7 * t)) & 0x7F)) << (8 * t)
            prefix = prefix << 1

            total = total << valueSizeBits
            total += value
            total = prefix << self.getBinaryLength(total) | total

        return total

    def getResultBytes(self, sizeBytes=None) -> bytes:
        """
        Get the result in bytes
        :param sizeBytes: number of bytes to fix to
        :return: size in bytes
        """
        return intToBytes(self.getResult(), sizeBytes if sizeBytes else self.getBinSizeBytes())

    def populate(self, paramPopulation: int) -> None:
        """
        Populate the bin and dimensions values
        :param paramPopulation: the population
        :return: None
        """

        numberOfDynamicBins = self.getNumberOfDynamicBins()

        total = paramPopulation
        totalDynamicBinSizes = []
        for t in range(numberOfDynamicBins):
            bit_size = self.getBinaryLength(total)
            dynamicBinSize = 0
            i = 0
            while ((bit_size - i * 8) - 1) >= 0 and (total >> (v := (bit_size - i * 8)) - 1):
                importantBits = (total >> (v - 8)) & 0x7F
                dynamicBinSize = (dynamicBinSize << 7) + importantBits
                total = total & (2 ** (v - 8) - 1)
                i += 1
            totalDynamicBinSizes.append(dynamicBinSize)
            total = total & ((2 ** self.getBinaryLength(total)) - 1)

        for index, (attribute, attribute_size) in enumerate(reversed(self.getDimensions())):
            if attribute_size is ArbitraryValue.DYNAMIC:
                attribute_size = totalDynamicBinSizes.pop(0)

            self.getDimensionValues()[self.getNumberOfBins() - index - 1] = total & ((2 ** attribute_size) - 1)
            total = total >> attribute_size

    """
            Attributes
    """

    def getAttributeSize(self, paramAttribute: Any) -> int | None:
        """
        Get the size of the attribute
        :param paramAttribute: The attribute to get the size of
        :return: None if the attribute doesnt exist or the int size of the attribute
        """
        for attribute, attribute_size in self.getDimensions():
            if not attribute == paramAttribute:
                continue

            if attribute_size == ArbitraryValue.DYNAMIC:
                attributeValue = self.getAttribute(attribute)
                return 0 if attributeValue == 0 else self.getBinaryLength(attributeValue)

            return attribute_size
        return None

    def setAttribute(self, paramAttribute: Any, paramValue: int | bytes | ArbitraryValue) -> None:
        """
        Set the attribute
        :param paramAttribute: attribute to set
        :param paramValue: the value to set it to
        :return: None
        """

        if isinstance(paramValue, bytes):
            paramValue = int.from_bytes(paramValue, byteorder="big")

        for index, (attribute, attribute_size) in enumerate(self.getDimensions()):
            if not attribute == paramAttribute:
                continue

            if paramValue is ArbitraryValue.RANDOMISE:
                if attribute_size is ArbitraryValue.DYNAMIC:
                    raise BinarySequencerException(None, BinarySequencerException.CANNOT_RANDOMISE_DYNAMIC_BIN)

                self.getDimensionValues()[index] = random.getrandbits(attribute_size)
                continue

            if (attribute_size != ArbitraryValue.DYNAMIC) and paramValue >> attribute_size > 0:
                raise BinarySequencerException(None, BinarySequencerException.ATTRIBUTE_TOO_LARGE)

            self.getDimensionValues()[index] = paramValue

    def getAttribute(self, *paramAttribute: Any) -> int | tuple[int]:
        """
        Get the result for the attributes
        :param paramAttribute: list of attributes
        :return: attribute values
        """

        values = [0] * len(paramAttribute)
        for index, (attribute, attribute_size) in enumerate(self.getDimensions()):
            if attribute not in paramAttribute:
                continue

            values[paramAttribute.index(attribute)] = self.getDimensionValues()[index]

        return values[0] if len(values) == 1 else tuple(values)

    def getAttributeBytes(self, *paramAttribute: Any) -> bytes | tuple[bytes]:
        """
        Get the attribute value in bytes
        :param paramAttribute: attributes to get
        :return: attribute value in bytes
        """
        results = [intToBytes(self.getAttribute(dimension), int(math.ceil(self.getAttributeSize(dimension) / 8)))
                   for dimension in paramAttribute]

        return results[0] if len(results) == 1 else tuple(results)

    def containsAttribute(self, paramDimension: str) -> bool:
        """
        Check if bin contains attribute
        :param paramDimension: The attribute
        :return: bool if it contains
        """
        attribute_size = self.getAttributeSize(paramDimension)
        return attribute_size is not None

    """
            Constructors
    """

    def __str__(self) -> str:
        return str(dict(
            [(attribute, value) for (attribute, _), value in zip(self.getDimensions(), self.getDimensionValues())]))

    def __len__(self) -> int:
        return self.getBinSize()


def getBinSize(paramDimensions: list) -> int:
    """
    Get bin size from dimensions
    :param paramDimensions: dimensions to add
    :return: bin size (int)
    """
    if not all([isinstance(dimension, tuple) and len(dimension) == 2 or len(dimension) == 3
                for dimension in paramDimensions]):
        raise BinarySequencerException(None, BinarySequencerException.INVALID_DIMENSIONS)

    for index, dimension in enumerate(paramDimensions):
        if len(dimension) == 2:
            continue
        paramDimensions[index] = dimension[0], dimension[1]

    return sum([b for _, b in paramDimensions])


def getBinSizeBytes(paramDimensions: list) -> int:
    """
    Get the bin size in
    :param paramDimensions:
    :return:
    """
    return int(math.ceil(getBinSize(paramDimensions) / 8))


def getBinFromSequence(paramSequence: list, paramBitsPerCharacter: int) -> Bin:
    """
    Convert a sequence to a bin
    :param paramSequence: The sequence to be put into a bin
    :param paramBitsPerCharacter: Number of characters per bit
    :return:
    """
    created_bin = Bin([(str(n), paramBitsPerCharacter) for n in range(len(paramSequence))])
    for index, item in enumerate(paramSequence):
        created_bin.setAttribute(str(index), item)

    return created_bin


def dropAttribute(paramBin: Bin, *paramDimension: str) -> Bin:
    """
    Remove an attribute from a bin
    :param paramBin: the bin to remove attribute from
    :param paramDimension: the dimensions of the bin
    :return: New bin
    """
    new_dimensions = []

    for dimensionName, dimensionSize in paramBin.getDimensions():
        if dimensionName not in paramDimension:
            new_dimensions.append((dimensionName, dimensionSize))

    new_bin = Bin(new_dimensions)

    for dimensionName, _ in new_bin.getDimensions():
        new_bin.setAttribute(dimensionName, paramBin.getAttribute(dimensionName))

    return new_bin


def getAttributeSize(paramDimensions: list[tuple], *paramAttribute: Any) -> tuple | int:
    """
    Get the size of an attribute
    :param paramDimensions: The dimensions of bin
    :param paramAttribute: The attribute
    :return:
    """
    results = [dict(paramDimensions).get(attribute, None) for attribute in paramAttribute]
    return results[0] if len(results) == 1 else tuple(results)


def getAttributeSizeBytes(paramDimensions: list[tuple], *paramAttribute: Any) -> tuple | int:
    """
    Get the attribute size in bytes not bits
    :param paramDimensions: The dimensions of the bin
    :param paramAttribute: The attribute
    :return:
    """
    results = getAttributeSize(paramDimensions, paramAttribute)
    return results[0] if len(results) == 1 else tuple(results)


def intToBytes(paramInt: int, paramSizeBytes: int) -> bytes:
    """
    Convert int to bytes
    :param paramInt: int to convert
    :param paramSizeBytes: number of bytes
    :return: bytes
    """
    characters = []
    for index in range(paramSizeBytes):

        characterInt = paramInt & 0xFF
        characters.insert(0, characterInt.to_bytes(1, byteorder="big"))
        paramInt = paramInt >> 8

    return b"".join(characters)
