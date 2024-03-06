import hashlib
from threading import Lock

from Properties import CHANNEL_BIN_DIMENSIONS, CHANNEL_INFO_BIN_DIMENSIONS
from channel import Service
from utils.Base85 import base85ToInt
from utils.BinarySequencer import Bin, getBinSize


class EntryScanService(Service.ServiceThread):
    def __init__(self, paramChannelID: str, paramLock: Lock, paramDirectoryEntries: list, paramResult: list):
        super().__init__(Service.ServiceType.TERMINAL_SCAN_TH)

        self.__channelID: str = paramChannelID
        self.__lock: Lock = paramLock
        self.__directoryEntries: list = paramDirectoryEntries
        self.__result = paramResult

    def getChannelID(self) -> str:
        """
        Get the channel ID
        :return: channel ID (str)
        """
        return self.__channelID

    def getDirectoryEntries(self) -> list:
        """
        Get the directory entries
        :return:
        """
        return self.__directoryEntries

    def getLock(self) -> Lock:
        """
        Get the main lock
        :return: Terminal Scan lock
        """
        return self.__lock

    def getResult(self) -> list:
        """
        Get the result
        :return: Result
        """
        return self.__result

    def setResult(self, paramResult: Bin) -> None:
        """
        Set result value
        :param: The result info bin
        :return: None
        """
        self.__result.append(paramResult)

    def getNextDirectoryEntry(self) -> str | None:
        """
        Returns the next directory entry to scan
        :return:
        """
        with self.getLock():
            if len(self.getDirectoryEntries()) > 0 and not len(self.getResult()):
                return self.getDirectoryEntries().pop()
            return None

    def run_safe(self):
        while (entry := self.getNextDirectoryEntry()) is not None:
            intValueEntry = base85ToInt(entry)

            entry_bin = Bin(CHANNEL_BIN_DIMENSIONS, population=intValueEntry).getAttribute("CHANNEL_INFO_BIN")
            info_bin = Bin(CHANNEL_INFO_BIN_DIMENSIONS, population=entry_bin)

            # Reverse encryption
            info_hash = hashlib.sha512(self.getChannelID().encode()).hexdigest()

            info_bin.xor(int(info_hash, 16))

            assert getBinSize(CHANNEL_INFO_BIN_DIMENSIONS) == info_bin.getBinSize()

            bin_authorisation_lo, bin_authorisation_hi = info_bin.getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")
            if bin_authorisation_lo - bin_authorisation_hi == 0:  # Authorisation does not match
                self.setResult(info_bin)
