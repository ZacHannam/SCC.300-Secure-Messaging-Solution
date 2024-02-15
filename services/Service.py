from threading import Thread
from enum import Enum, auto


class ServiceType(Enum):
    TERMINAL_VALIDATE           = auto()  # Upload key to terminal                                C     REMOVE

    SERVER_PUBLISH              = auto()  # Create an entry on the directory                      C

    TERMINAL_SCAN               = auto()  # Scans the terminal using channel key                  C
    TERMINAL_SCAN_TH            = auto()  # Individual scanner process (faster than one thread)   C

    SERVER_HOST                 = auto()  # Host the channel                                      C
    SERVER_CONNECTION           = auto()  # Connect to the client                                 W
    SERVER_ALIVE                = auto()  # Runs to check if the client is still alive            C
    SERVER_TUNNEL               = auto()  # Service to tunnel                                     C

    CLIENT_CONNECTION           = auto()  # Connect to the host                                   W

    SEND_PACKET                 = auto()  # Send a packet between client and host                 C
    PACKET_COLLECTOR            = auto()  # Service to collect packets and present them whole     C


class ServiceThread(Thread):
    def __init__(self, paramThreadType: ServiceType, target=None, name=None, args=(), kwargs=None):
        super(ServiceThread, self).__init__(target=target, name=name)
        self.args, self.kwargs = args, kwargs

        self.__threadType = paramThreadType

    def getThreadType(self) -> ServiceType:
        return self.__threadType
