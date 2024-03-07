import random
from threading import Event
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from Properties import CHANNEL_USER_DISPLAY_NAME_MAX, NAMES_LIST_FILE, TERMINAL_PROTOCOL, RSA_KEY_SIZE, \
    MAX_FILE_SIZE_BYTES, SEND_HIDDEN_FILES
from channel.client.ClientConnectionService import ClientConnectionService
from channel.client.TerminalScanService import TerminalScanService
from utils.BinarySequencer import Bin, getBinSize
from Properties import CHANNEL_INFO_BIN_DIMENSIONS
from utils.Language import info
from utils.MessengerExceptions import ClientException


class Client:
    def __init__(self, paramServerTerminal: str, paramChannelID: str, paramServerIP: str, paramServerPort: int,
                 name=None, server_secret: str | None = None):
        """
        A client that connects to a server
        :param paramServerTerminal: Server Terminal URL
        :param paramChannelID: Channel ID of the Server
        :param paramServerIP: IP of the Server
        :param paramServerPort: Server Port
        :param name: Connection display name
        """

        # Validate that the server terminal starts with an accepted protocol
        if not any([paramServerTerminal.startswith(protocol) for protocol in TERMINAL_PROTOCOL]):
            raise ClientException(None, ClientException.INVALID_TERMINAL_URL)

        self.__serverTerminal: str = paramServerTerminal  # Server Terminal URL
        self.__serverIP: str = paramServerIP  # Server IP (x.x.x.x / a:a:a:a:a:a:a:a / http(s)://...)
        self.__serverPort: int = paramServerPort  # Server Port
        self.__channelID: str = paramChannelID  # Server Channel Name/ID
        self.__serverSecret: str | None = server_secret

        # Generate a display name or generate one
        self.__clientDisplayName = name if name is not None else generateDisplayName()

        self.__privateKey: RSAPrivateKey = generatePrivateKey()  # Create private and public RSA key for client

        self.__stop = Event()  # Stop Event

        self.__serverPublicKey = None  # Store the server public key
        self.__clientConnectService = None  # The client's connection to the server thread

        # Connect to the server
        self.connectToServer()

    """
            Getter Methods
    """

    def getServerSecret(self) -> str | None:
        """
        Return the server secret if it is set
        :return:
        """
        return self.__serverSecret

    def getStopEvent(self) -> Event:
        """
        gets the stop event
        :return: Stop event
        """
        return self.__stop

    def getChannelID(self) -> str:
        """
        returns the server channel id
        :return: channel id (str)
        """
        return self.__channelID

    def getServerTerminal(self) -> str:
        """
        returns the server terminal
        :return: terminal url (str)
        """
        return self.__serverTerminal

    def getServerIP(self) -> str:
        """
        returns the server IP
        :return: server IP (x.x.x.x / http(s)://... / a:a:a:a:a:a:a:a)
        """
        return self.__serverIP

    def getServerPort(self) -> int:
        """
        returns the server port
        :return: server port (int)
        """
        return self.__serverPort

    def getClientDisplayName(self) -> str:
        """
        returns the client display name
        :return: display name (str)
        """
        return self.__clientDisplayName

    """
            RSA
    """

    def getPrivateKey(self) -> RSAPrivateKey:
        """
        Returns the private key RSA
        :return: Client Private Key (RSA)
        """
        return self.__privateKey

    def setServerPublicKey(self, paramPublicKey: RSAPublicKey) -> None:
        """
        Sets the server public key
        :param paramPublicKey: Server Public Key (RSA)
        :return: None
        """
        self.__serverPublicKey = paramPublicKey

    def getServerPublicKey(self) -> RSAPublicKey:
        """
        Returns the server public key (RSA)
        :return: Server Public Key (RSA)
        """
        return self.__serverPublicKey

    """
            SERVER
    """

    def leaveServer(self) -> None:
        """
        Leave the server and close the client connection
        :return: None
        """
        try:
            self.getClientConnection().stop()  # Stop the server
        except ConnectionAbortedError:  # Catch any errors thrown
            raise ClientException(None, ClientException.FAILED_TO_LEAVE_SERVER)

    def sendMessage(self, paramMessage: str) -> None:
        """
        Send a message to the server in the form of text
        :param paramMessage: Message sent to other clients and server
        :return: None
        """
        self.getClientConnection().sendTextMessage(paramMessage)  # Send message through connection

    def sendFile(self, paramFilePath: str) -> None:
        """
        Send a file to server
        :param paramFilePath: File or directory path
        :return: None
        """
        try:
            files = recursiveFileFinder(paramFilePath)  # Get files from file path
        except FileNotFoundError:
            raise ClientException(self.getStopEvent(), ClientException.FAILED_TO_FIND_FILE)

        directory = os.path.dirname(paramFilePath)

        # Iterate over files
        for file in files:
            file_stats = os.stat(file)
            if file_stats.st_size > MAX_FILE_SIZE_BYTES:
                raise ClientException(self.getStopEvent(), ClientException.EXCEEDS_MAX_FILE_SIZE)

            file_name = file[len(directory) + 1:]
            info("SENDING_FILE", file_name=file_name, channel_id=self.getChannelID())

            with open(file, "rb") as openFile:
                file_bytes = openFile.read()

            self.getClientConnection().sendFileBytes(file_name, file_bytes)

    """
            CONNECT
    """

    def getClientConnection(self) -> ClientConnectionService:
        """
        Returns the client connection
        :return: Client socket to server
        """
        return self.__clientConnectService

    def connectToServer(self) -> None:
        """
        Establish socket with the server
        :return: None
        """

        # Start the client connection service
        clientConnectService = ClientConnectionService(self.getServerIP(), self.getServerPort(), self.getStopEvent(),
                                                       self.getClientDisplayName(), self.getChannelID(),
                                                       self.getPrivateKey(), self.getServerPublicKey(),
                                                       self.getServerSecret())
        clientConnectService.start()  # Start the client connection service

        self.__clientConnectService = clientConnectService  # Set the client connection

        if not clientConnectService.getReadyEvent().wait(timeout=20):  # Wait for socket connection to be established
            raise ClientException(None, ClientException.FAILED_TO_CONNECT_TIMEOUT)  # error when timeout happens


def generatePrivateKey() -> RSAPrivateKey:
    """
    Generate the public and private key
    :return: Private Key (RSA)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,  # The size of the key in bits
    )

    return private_key


def generateDisplayName(max_length=CHANNEL_USER_DISPLAY_NAME_MAX) -> str:
    """
    Generate a display name for the client
    :param max_length: The max length of the display name
    :return: The display name generated
    """

    with open(NAMES_LIST_FILE) as nameFile:  # Read the names in the names list
        names = nameFile.readlines()

        selectName = lambda: names[random.randint(0, len(names))]  # Select a random name / line
        while (selectedName := selectName()) in ("", None):  # Make sure the name selected is not empty (double check)
            continue

    selectedName += "".join(random.choices("0123456789", k=random.randint(0, 3)))  # Add numbers to the end of the name

    assert selectedName[:max_length] not in (None, "")  # Assert that the name is not empty of null

    return selectedName[:max_length]  # Return the name selected up to the max size


def getClientFromBin(paramTerminal: str, paramChannelID: str, paramBin: Bin,
                     name=None, server_secret=None) -> Client:
    """
    Create a client object from the client binary sequencer
    :param server_secret: Server secret
    :param paramTerminal: The terminal URL
    :param paramChannelID: The channel ID
    :param paramBin: The client info bin
    :param name: The client display name
    :return: Client generated
    """

    assert getBinSize(CHANNEL_INFO_BIN_DIMENSIONS) == paramBin.getBinSize()  # Assert that the bin sizes matches

    # 1) Check if the authorisation matches
    bin_authorisation_lo, bin_authorisation_hi = paramBin.getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")
    if not bin_authorisation_lo - bin_authorisation_hi == 0:  # Authorisation does not match
        raise ClientException(None, ClientException.FAILED_TO_CREATE_CLIENT_FROM_BIN)

    # 2) Get the IP from the bin
    ip_type, ip_placement, ip = paramBin.getAttribute("IP_TYPE", "IP_PLACEMENT", "IP")

    # Find the IP length from the IP type
    match ip_type:
        case 0:  # IPType.IPv4:  # IPv4
            ip_size = 32
        case 1:  # IPType.IPv6:  # IPv6
            ip_size = 128
        case 2:  # IPType.Tunnel:  # Tunnel (http(s))
            ip_size = ip_placement
        case _:  # Should not ready here
            raise ClientException(None, ClientException.INVALID_IP_TYPE)

    # Create a temporary bin to decode the IP placement
    ip_bin = Bin([("A", ip_placement),
                  ("IP", ip_size),
                  ("Z", paramBin.getAttributeSize("IP") - ip_placement - ip_size)], population=ip)

    # Convert the IP back to a string
    match ip_type:
        case 0:  # IPType.IPv4:  # IPv4

            ip = ".".join([str(n) for n in list(ip_bin.getAttribute("IP").to_bytes(4, byteorder="big", signed=False))])
        case 1:  # IPType.IPv6:  # Ipv4

            ip_bin = Bin([(c, 16) for c in 'ABCDEFGH'], population=ip_bin.getAttribute("IP"))
            ip = ":".join([hex(r) for r in ip_bin.getAttribute('A', 'B', 'C', 'D', 'E', 'F', 'G')])
        case 2:  # IPType.Tunnel:  # Tunneling (http(s))

            ip_bin = Bin([("A", ip_size),
                          ("IP", paramBin.getAttributeSize("IP") - ip_size)], population=ip)

            ip = ip_bin.getAttributeBytes("IP").decode('utf-8')
        case _:  # Should not reach here
            raise ClientException(None, ClientException.INVALID_IP_TYPE)

    # 4) Get the port of the server
    port = paramBin.getAttribute("PORT")

    # 5) Generate and return the generated client
    return Client(paramTerminal, paramChannelID, ip, port, name=name, server_secret=server_secret)


def getClientFromTerminalScan(paramTerminal: str, paramChannelID: str, name=None, server_secret=None) -> Client:
    """
    Run a terminal scan to find the desired server and create a user from it
    :param server_secret: Server secret
    :param paramTerminal: The Terminal to scan
    :param paramChannelID: The channel id to search for
    :param name: The display name to generate
    :return: Client generated from scan
    """
    terminalScanService = TerminalScanService(paramTerminal, paramChannelID)  # Start the terminal scan service
    terminalScanService.start()
    terminalScanService.join()  # Wait for it to gather a result

    if terminalScanService.getResult() is None:  # Check that it got a valid result
        raise ClientException(None, ClientException.NO_CHANNEL_ON_TERMINAL)

    return getClientFromBin(paramTerminal, paramChannelID, terminalScanService.getResult(),
                            name=name, server_secret=server_secret)  # Creates a client from the collected information


def recursiveFileFinder(paramFolderPath: str) -> list[str]:
    """
    Return all files in folder
    :param paramFolderPath: Folder path
    :return: list of file paths
    """
    files = []

    if not os.path.isdir(paramFolderPath):
        return [paramFolderPath]

    for file in os.listdir(paramFolderPath):
        filePath = os.path.join(paramFolderPath, file)
        if os.path.isdir(filePath):
            files += recursiveFileFinder(filePath)
        else:
            if not os.path.basename(file).startswith(".") or SEND_HIDDEN_FILES:  # Hidden files might not be sent
                files.append(filePath)
    return files
