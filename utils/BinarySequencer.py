from functools import lru_cache
import random
from enum import Enum, auto
import math
from typing import Any


class ArbitraryValue(Enum):
    RANDOMISE = auto()  # Randomise when used in
    DYNAMIC = auto()  # Makes a dynamic byte


class Bin:
    def __init__(self, paramDimensions: list, population=0):
        if not all([isinstance(dimension, tuple) and len(dimension) == 2 or len(dimension) == 3
                    for dimension in paramDimensions]):
            raise ValueError("Dimensions do not fit [(a, b, ?), ...]")

        if isinstance(population, bytes):
            population = int.from_bytes(population, byteorder="big")

        if not isinstance(population, int):
            raise ValueError("Population must be an integer or bytes")

        self.__dimensions = paramDimensions
        self.__dimension_values = [0] * self.getNumberOfBins()

        setValues = []
        for index, dimension in enumerate(paramDimensions):
            if len(dimension) == 2:
                continue

            setValues.append((dimension[0], dimension[2]))
            paramDimensions[index] = dimension[0], dimension[1]

        self.__dimensions = paramDimensions

        for dimension, value in setValues:
            self.setAttribute(dimension, value)

        if population != 0:
            self.populate(population)

    """
            Dimension Methods
    """

    def __getDimensionValues(self) -> list:
        return self.__dimension_values

    @lru_cache
    def getDimensions(self) -> list[tuple]:
        return self.__dimensions

    """
            General Bin Methods
    """

    @lru_cache
    def getNumberOfBins(self):
        return len(self.__dimensions)

    def getBinSize(self):
        total = 0
        for attribute, attribute_size in self.getDimensions():

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

    def getBinSizeBytes(self):
        return math.ceil(self.getBinSize() / 8)

    def xor(self, paramInt: int):
        if self.__getNumberOfDynamicBins():
            raise RuntimeError("Cannot use xor when there is a dynamic bin")

        self.populate(self.getResult() ^ paramInt)

    """
            Results And Populate
    """

    @lru_cache
    def __getBinaryLength(self, paramInt: int) -> int:
        if paramInt == 0:
            return 0

        return int(math.ceil(math.log(paramInt, 2)))

    @lru_cache
    def __getNumberOfDynamicBins(self) -> int:
        return sum([binSize == ArbitraryValue.DYNAMIC for _, binSize in self.getDimensions()])

    def getResult(self):
        total = 0
        for (attribute, attribute_size), value in zip(self.getDimensions(), self.__getDimensionValues()):
            if attribute_size is not ArbitraryValue.DYNAMIC:
                total = total << attribute_size
                total += value
                continue

            if value == 0:
                total = 0x100 << self.__getBinaryLength(total) | total
                continue

            valueSizeBits = self.__getBinaryLength(value)
            logValueSizeBits = self.__getBinaryLength(valueSizeBits)

            prefix = 0
            for t in range(int(math.ceil(logValueSizeBits / 7))):
                prefix += (0x80 | ((valueSizeBits >> (7 * t)) & 0x7F)) << (8 * t)
            prefix = prefix << 1

            total = total << valueSizeBits
            total += value
            total = prefix << self.__getBinaryLength(total) | total

        return total

    def getResultBytes(self, sizeBytes=None):
        return intToBytes(self.getResult(), sizeBytes if sizeBytes else self.getBinSizeBytes())

    def populate(self, paramPopulation):

        numberOfDynamicBins = self.__getNumberOfDynamicBins()

        total = paramPopulation
        totalDynamicBinSizes = []
        for t in range(numberOfDynamicBins):
            bit_size = self.__getBinaryLength(total)
            dynamicBinSize = 0
            i = 0
            while total >> (v := (bit_size - i * 8)) - 1:
                importantBits = (total >> (v - 8)) & 0x7F
                dynamicBinSize = (dynamicBinSize << 7) + importantBits
                total = total & (2 ** (v - 8) - 1)
                i += 1
            totalDynamicBinSizes.append(dynamicBinSize)
            total = total & ((2 ** self.__getBinaryLength(total)) - 1)

        for index, (attribute, attribute_size) in enumerate(reversed(self.getDimensions())):
            if attribute_size is ArbitraryValue.DYNAMIC:
                attribute_size = totalDynamicBinSizes.pop(0)

            self.__getDimensionValues()[self.getNumberOfBins() - index - 1] = total & ((2 ** attribute_size) - 1)
            total = total >> attribute_size

    """
            Attributes
    """

    def getAttributeSize(self, paramAttribute) -> int | None:
        for attribute, attribute_size in self.getDimensions():
            if not attribute == paramAttribute:
                continue

            if attribute_size == ArbitraryValue.DYNAMIC:
                attributeValue = self.getAttribute(attribute)
                return 0 if attributeValue == 0 else self.__getBinaryLength(attributeValue)

            return attribute_size
        return None

    def setAttribute(self, paramAttribute: Any, paramValue: int | bytes | ArbitraryValue):

        if isinstance(paramValue, bytes):
            paramValue = int.from_bytes(paramValue, byteorder="big")

        for index, (attribute, attribute_size) in enumerate(self.getDimensions()):
            if not attribute == paramAttribute:
                continue

            if paramValue is ArbitraryValue.RANDOMISE:
                if attribute_size is ArbitraryValue.DYNAMIC:
                    raise RuntimeError("Cannot apply a randomised value to a dynamic bin")

                self.__getDimensionValues()[index] = random.getrandbits(attribute_size)
                continue

            if (attribute_size != ArbitraryValue.DYNAMIC) and paramValue >> attribute_size > 0:
                raise OverflowError("Attribute value does not fit in container")

            self.__getDimensionValues()[index] = paramValue

    def getAttribute(self, *paramAttribute: Any) -> int | tuple:

        values = [0] * len(paramAttribute)
        for index, (attribute, attribute_size) in enumerate(self.getDimensions()):
            if attribute not in paramAttribute:
                continue

            values[paramAttribute.index(attribute)] = self.__getDimensionValues()[index]

        return values[0] if len(values) == 1 else tuple(values)

    def getAttributeBytes(self, *paramAttribute: Any) -> bytes | tuple:
        results = [intToBytes(self.getAttribute(dimension), int(math.ceil(self.getAttributeSize(dimension) / 8)))
                   for dimension in paramAttribute]

        return results[0] if len(results) == 1 else tuple(results)

    def containsAttribute(self, paramDimension: str):
        attribute_size = self.getAttributeSize(paramDimension)
        return attribute_size is not None

    """
            Constructors
    """

    def __str__(self) -> str:
        return str(dict(
            [(attribute, value) for (attribute, _), value in zip(self.getDimensions(), self.__getDimensionValues())]))

    def __len__(self) -> int:
        return self.getBinSize()


def getBinSize(paramDimensions: list) -> int:
    if not all([isinstance(dimension, tuple) and len(dimension) == 2 or len(dimension) == 3
                for dimension in paramDimensions]):
        raise ValueError("Dimensions do not fit [(a, b, ?), ...]")


    for index, dimension in enumerate(paramDimensions):
        if len(dimension) == 2:
            continue
        paramDimensions[index] = dimension[0], dimension[1]

    return sum([b for _, b in paramDimensions])


def getBinSizeBytes(paramDimensions: list) -> int:
    return int(math.ceil(getBinSize(paramDimensions) / 8))


def getBinFromSequence(paramSequence: list, paramBitsPerCharacter) -> Bin:
    created_bin = Bin([(str(n), paramBitsPerCharacter) for n in range(len(paramSequence))])
    for index, item in enumerate(paramSequence):
        created_bin.setAttribute(str(index), item)

    return created_bin


def dropAttribute(paramBin: Bin, *paramDimension: str):
    new_dimensions = []

    for dimensionName, dimensionSize in paramBin.getDimensions():
        if dimensionName not in paramDimension:
            new_dimensions.append((dimensionName, dimensionSize))

    new_bin = Bin(new_dimensions)

    for dimensionName, _ in new_bin.getDimensions():
        new_bin.setAttribute(dimensionName, paramBin.getAttribute(dimensionName))

    return new_bin


def getAttributeSize(paramDimensions: list[tuple], *paramAttribute: Any) -> tuple | int | None:
    results = [dict(paramDimensions).get(attribute, None) for attribute in paramAttribute]
    return results[0] if len(results) == 1 else tuple(results)


def intToBytes(paramInt: int, paramSizeBytes: int) -> bytes:
    characters = []
    for index in range(paramSizeBytes):

        characterInt = paramInt & 0xFF
        characters.insert(0, characterInt.to_bytes(1, byteorder="big"))
        paramInt = paramInt >> 8

    return b"".join(characters)
