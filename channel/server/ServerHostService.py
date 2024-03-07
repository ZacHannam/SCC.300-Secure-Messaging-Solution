import socket
from threading import Event

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from utils.MessengerExceptions import ServerException
from channel.server.ServerConnectionService import ServerConnectionService
from channel import Service


class ServerHostService(Service.ServiceThread):
    def __init__(self, paramServerPort: int, paramStopEvent: Event,
                 paramChannelID: str, paramServerPrivateKey: RSAPrivateKey, paramServerMaxUsers: int,
                 paramServerUserList: list, paramServerBanList: list, paramServerSecret: str):
        super().__init__(Service.ServiceType.SERVER_HOST)

        self.__serverPort = paramServerPort  # Port the server is running on
        self.__stop = paramStopEvent  # Server stop event

        self.__channelID: str = paramChannelID  # Channel ID
        self.__serverPrivateKey: RSAPrivateKey = paramServerPrivateKey  # Server Private Key
        self.__serverSecret: str = paramServerSecret

        # For server Authentication
        self.__serverMaxUsers: int = paramServerMaxUsers  # Max number of users on the server
        self.__serverUserList: list[ServerConnectionService] = paramServerUserList  # List of of users on the server
        self.__serverBanList: list[str] = paramServerBanList  # List of banned users on the server

        self.__ready = Event()


    """
            Getter Methods
    """

    def getServerSecret(self) -> str:
        """
        Get the server secret
        :return: Server secret (str)
        """
        return self.__serverSecret

    def getServerPort(self) -> int:
        """
        Returns the server port
        :return: The server port
        """
        return self.__serverPort

    def getStopEvent(self) -> Event:
        """
        Get the stop event
        :return: The stop event
        """
        return self.__stop

    def getReadyEvent(self) -> Event:
        """
        Ready Event for the host service
        :return: The ready event
        """
        return self.__ready

    def getMaxServerUsers(self) -> int:
        """
        Returns max number of server users
        :return: Number of user slots on the server
        """
        return self.__serverMaxUsers

    def getServerUserList(self) -> list:
        """
        Returns the list of users currently on the server
        :return: List of server users
        """
        return self.__serverUserList

    def getServerBanList(self) -> list:
        """
        Returns the list of users banned on the server
        :return: List of ips banned on the server
        """
        return self.__serverBanList

    def getServerPrivateKey(self) -> RSAPrivateKey:
        """
        Returns the server private key
        :return: Server private key (RSAPrivateKey)
        """
        return self.__serverPrivateKey

    def getChannelID(self) -> str:
        """
        Gets the server channel id
        :return:
        """
        return self.__channelID

    def run_safe(self):
        host = socket.gethostname()
        port = self.getServerPort()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            try:
                server_socket.bind((host, port))
            except OSError:
                raise ServerException(self.getStopEvent(), ServerException.SERVER_ALREADY_ON_PORT)
            self.getReadyEvent().set()

            server_socket.listen()
            server_socket.settimeout(1.0)

            while not self.getStopEvent().is_set():
                try:
                    # Accept new connection
                    connection, client_address = server_socket.accept()

                    # Create a new server connection
                    serverConnectionService = ServerConnectionService(client_address, connection,
                                                                      self.getChannelID(),
                                                                      self.getServerPrivateKey(),
                                                                      self.getMaxServerUsers(),
                                                                      self.getServerUserList(),
                                                                      self.getServerBanList(),
                                                                      self.getServerSecret())

                    serverConnectionService.start()
                except socket.timeout:
                    pass  # Refresh the stop event flag

            server_socket.close()
