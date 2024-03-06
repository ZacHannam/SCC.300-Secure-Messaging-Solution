from threading import Lock
import requests

from utils.MessengerExceptions import ClientException
from channel.client.EntryScanService import EntryScanService
from channel import Service
from utils.BinarySequencer import Bin


class TerminalScanService(Service.ServiceThread):
    def __init__(self, paramTerminal: str, paramChannelID: str):
        """
        Scan the terminal to find channel bin
        :param paramTerminal: Terminal to scan
        :param paramChannelID: Channel to find
        """
        super().__init__(Service.ServiceType.TERMINAL_SCAN)

        self.__terminal: str = paramTerminal
        self.__channelID: str = paramChannelID

        self.__lock: Lock = Lock()
        self.__directoryEntries: list = []

        self.__result: list = []

    """
                GETTER
    """

    def getResult(self) -> Bin | None:
        """
        Get the result
        :return: result (Bin)
        """
        return None if not len(self.__result) else self.__result[0]

    def getLock(self) -> Lock:
        """
        Get threading lock
        :return: threading Lock (Lock)
        """
        return self.__lock

    def getTerminal(self) -> str:
        """
        Get terminal URL
        :return: terminal URL (str)
        """
        return self.__terminal

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

    """
                METHODS
    """

    def getAllDirectoryEntries(self):
        """
        Get all the directories on the terminal page
        :return:
        """
        response = requests.get(self.getTerminal())

        if response.status_code != 200:
            raise ClientException(None, ClientException.FAILED_VALIDATE_TERMINAL)


        try:
            self.__directoryEntries = [key for key in response.json().keys()]
        except requests.exceptions.ContentDecodingError:
            raise ClientException(None, ClientException.FAILED_VALIDATE_TERMINAL)

    def findChannelEntry(self, threads=12):
        """
        Find the channel entry by spawning search threads
        :param threads:
        :return:
        """

        numberOfThreads = min(threads, len(self.getDirectoryEntries()))

        entryScanners = [EntryScanService(self.getChannelID(), self.getLock(),
                                          self.getDirectoryEntries(), self.__result)
                         for _ in range(numberOfThreads)]

        for scanner in entryScanners:
            scanner.start()

        for scanner in entryScanners:
            scanner.join()

    def run_safe(self):
        self.getAllDirectoryEntries()
        self.findChannelEntry()
