import base64
from threading import Event
import requests

from utils.MessengerExceptions import ServerException
from channel import Service
from utils.BinarySequencer import Bin


class PublishChannelService(Service.ServiceThread):
    def __init__(self, paramStopEvent: Event, paramTerminal: str, paramChannelID: str,
                 paramIsPublic: bool, paramChannelBin: Bin):
        """
        Method to publish channel to the terminal
        :param paramStopEvent: Server stop event
        :param paramTerminal: Server terminal url
        :param paramChannelID: Server channel ID
        :param paramIsPublic: Server public setting
        :param paramChannelBin: Server channel bin
        """
        super().__init__(Service.ServiceType.SERVER_PUBLISH)

        self.__channelBin: Bin = paramChannelBin
        self.__stopEvent: Event = paramStopEvent
        self.__terminal: str = paramTerminal
        self.__channelID: str = paramChannelID
        self.__isPublic: bool = paramIsPublic
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

    def isPublic(self) -> bool:
        """
        Returns if the server is public
        :return: If the server is public
        """
        return self.__isPublic

    def getChannelID(self) -> str:
        """
        Returns the channel ID
        :return: Channel ID
        """
        return self.__channelID

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

    def publish(self) -> None:
        """
        Attempts to publish the channel to the terminal and saves value in result
        :return: None
        """

        channelBinBytes = self.getChannelBin().getResultBytes()

        try:
            json = {
                "CHANNEL_BYTES": base64.b64encode(channelBinBytes).decode('utf-8')
            }

            if self.isPublic():
                json["CHANNEL_ID"] = self.getChannelID()

            response = requests.post(f"{self.getTerminal()}/validate", json=json)  # Send validation post request

            self.__result = response.json()

        except (requests.RequestException, requests.exceptions.ContentDecodingError):
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_PUBLISH_CHANNEL)

    def run_safe(self):
        self.publish()
