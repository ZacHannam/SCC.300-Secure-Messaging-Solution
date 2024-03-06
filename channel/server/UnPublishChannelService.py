import base64
from threading import Event
import requests

from utils.MessengerExceptions import ServerException
from channel import Service
from utils.BinarySequencer import Bin


class UnPublishChannelService(Service.ServiceThread):
    def __init__(self, paramStopEvent: Event, paramTerminal: str, paramChannelBin: Bin ):
        """
        Method to unpublish channel
        :param paramTerminal: Server terminal
        :param paramStopEvent: Server stop event
        """
        super().__init__(Service.ServiceType.SERVER_UNPUBLISH)

        self.__terminal: str = paramTerminal
        self.__stopEvent: Event = paramStopEvent
        self.__channelBin: Bin = paramChannelBin
        self.__result: dict | None = None

    """
            Getter Methods
    """

    def getTerminal(self) -> str:
        """
        Returns the terminal url
        :return: Terminal URL server is using (str)
        """
        return self.__terminal

    def getChannelBin(self) -> Bin:
        """
        Returns the channel bin
        :return: Channel Bin
        """
        return self.__channelBin

    def getStopEvent(self) -> Event:
        """
        Returns the stop event
        :return: Stop event
        """
        return self.__stopEvent

    def getResult(self) -> dict:
        """
        Returns the result of the channel bin
        :return: Result of validating
        """
        return self.__result

    """
            Methods
    """

    def unpublish(self) -> None:
        """
        Attempts to unpublish channel in terminal and saves result
        :return:
        """

        try:

            channelBinBytes = self.getChannelBin().getResultBytes()

            json = {
                "CHANNEL_BYTES": base64.b64encode(channelBinBytes).decode('utf-8')
            }

            response = requests.post(f"{self.getTerminal()}/unvalidate", json=json)

            self.__result = response.json()

        except (requests.RequestException, requests.exceptions.ContentDecodingError):
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_UNPUBLISH_CHANNEL)

    def run_safe(self):
        self.unpublish()
