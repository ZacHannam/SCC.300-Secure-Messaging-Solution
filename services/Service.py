from threading import Thread
from enum import Enum, auto
from abc import ABC, abstractmethod
import traceback

from Language import info
from channel.MessengerExceptions import MessengerException


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
        super(ServiceThread, self).__init__(target=target, name=name)
        self.args, self.kwargs = args, kwargs

        self.__threadType = paramThreadType

    def getThreadType(self) -> ServiceType:
        return self.__threadType

    @abstractmethod
    def run_safe(self):
        raise NotImplementedError("run_safe method was not implemented!")

    def run(self) -> None:
        try:
            self.run_safe()
        except MessengerException as exception:
            info("SERVICE_EXCEPTION", exception=exception.message)
