import threading
import requests.exceptions
import hashlib

from services import Service
from Properties import CHANNEL_INFO_BIN_DIMENSIONS, CHANNEL_BIN_DIMENSIONS
from services.terminal.TerminalValidateService import TerminalValidateService
from utils.BinarySequencer import Bin, getBinSize
from utils.codecs.Base85 import base85ToInt


class TerminalScanService(Service.ServiceThread):
    def __init__(self, paramTerminal: str, paramChannelID: str):
        super().__init__(Service.ServiceType.TERMINAL_SCAN)

        self.__terminal = paramTerminal
        self.__channelID = paramChannelID

        self.__lock = threading.Lock()
        self.__directoryEntries = []

        self.__result = None

    """
                GETTER
    """

    def setResult(self, paramResult: Bin):
        self.__result = paramResult

    def getResult(self) -> Bin | None:
        return self.__result

    def getLock(self) -> threading.Lock:
        return self.__lock

    def getTerminal(self) -> str:
        return self.__terminal

    def getChannelID(self) -> str:
        return self.__channelID

    """
                METHODS
    """

    def getNextDirectoryEntry(self) -> str | None:
        with self.getLock():
            if len(self.__getDirectoryEntries()) > 0 and self.getResult() is None:
                return self.__getDirectoryEntries().pop()
            return None

    def __getDirectoryEntries(self) -> list:
        return self.__directoryEntries

    def __getAllDirectoryEntries(self):

        terminalValidateService = TerminalValidateService(self.getTerminal())
        terminalValidateService.start()
        terminalValidateService.join()

        if not terminalValidateService.getResult():
            raise RuntimeError(f"Failed to validate terminal {self.getTerminal()}")

        response = requests.get(self.getTerminal())

        if response.status_code != 200:
            raise requests.RequestException

        try:
            self.__directoryEntries = [key for key in response.json().keys()]
        except requests.exceptions.ContentDecodingError:
            pass

    def __findChannelEntry(self, threads=12):

        numberOfThreads = min(threads, len(self.__getDirectoryEntries()))

        entryScanners = [EntryScanService(self) for _ in range(numberOfThreads)]

        for scanner in entryScanners:
            scanner.start()

        for scanner in entryScanners:
            scanner.join()


    def run(self):
        self.__getAllDirectoryEntries()
        self.__findChannelEntry()


class EntryScanService(Service.ServiceThread):
    def __init__(self, paramTerminalScanThread: TerminalScanService):
        super().__init__(Service.ServiceType.TERMINAL_SCAN_TH)

        self.__terminalScanThread = paramTerminalScanThread

    def getTerminalScanThread(self) -> TerminalScanService:
        return self.__terminalScanThread

    def run(self):
        while (entry := self.getTerminalScanThread().getNextDirectoryEntry()) is not None:
            intValueEntry = base85ToInt(entry)

            entry_bin = Bin(CHANNEL_BIN_DIMENSIONS, population=intValueEntry).getAttribute("CHANNEL_INFO_BIN")
            info_bin = Bin(CHANNEL_INFO_BIN_DIMENSIONS, population=entry_bin)

            # Reverse encryption
            info_hash = hashlib.sha512(self.getTerminalScanThread().getChannelID().encode()).hexdigest()

            info_bin.xor(int(info_hash, 16))

            assert getBinSize(CHANNEL_INFO_BIN_DIMENSIONS) == info_bin.getBinSize()

            bin_authorisation_lo, bin_authorisation_hi = info_bin.getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")
            if bin_authorisation_lo - bin_authorisation_hi == 0:  # Authorisation does not match
                self.getTerminalScanThread().setResult(info_bin)
