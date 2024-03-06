from threading import Thread
from enum import Enum, auto
from abc import ABC, abstractmethod

from utils.Language import info
from utils.MessengerExceptions import MessengerException


class ServiceType(Enum):
    TERMINAL_VALIDATE           = auto()  # Upload key to terminal                                C

    SERVER_PUBLISH              = auto()  # Create an entry on the directory                      C
    SERVER_UNPUBLISH            = auto()  # Remove an entry on the directory using secret         C

    TERMINAL_SCAN               = auto()  # Scans the terminal using channel key                  C
    TERMINAL_SCAN_TH            = auto()  # Individual scanner process (faster than one thread)   C

    SERVER_HOST                 = auto()  # Host the channel                                      C
    SERVER_CONNECTION           = auto()  # Connect to the client                                 C
    SERVER_ALIVE                = auto()  # Runs to check if the client is still alive            C
    SERVER_TUNNEL               = auto()  # Service to tunnel                                     C

    CLIENT_CONNECTION           = auto()  # Connect to the host                                   C

    SEND_PACKET                 = auto()  # Send a packet between client and host                 C
    PACKET_COLLECTOR            = auto()  # Service to collect packets and present them whole     C


class ServiceThread(Thread, ABC):
    def __init__(self, paramThreadType: ServiceType, target=None, name=None, args=(), kwargs=None):
        """
        Abstract class implementation for Thread
        :param paramThreadType: The thread type used
        :param target: Parent Thread target
        :param name: Parent Thread name
        :param args: Parent thread args
        :param kwargs: Parent thread kwargs
        """
        super(ServiceThread, self).__init__(target=target, name=name)
        self.args, self.kwargs = args, kwargs  # Set args and kwargs in Thread parent

        self.__threadType = paramThreadType  # Thread type the service is using

    def getThreadType(self) -> ServiceType:
        """
        Get the thread type the service is using
        :return: Thread type
        """
        return self.__threadType

    @abstractmethod
    def run_safe(self):
        """
        Run safely using exception catching
        :return:
        """
        raise NotImplementedError("run_safe method was not implemented!")

    def run(self) -> None:
        try:
            self.run_safe()
        except MessengerException as exception:
            info("SERVICE_EXCEPTION", exception=exception.message)
