import os.path
import random
import re
import hashlib
import string
from functools import lru_cache
from threading import Event
import requests

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from Properties import CHANNEL_ID_LENGTH, CHANNEL_SECRET_KEY_LENGTH, DEFAULT_PORT_SERVER, CHANNEL_BIN_DIMENSIONS, \
    CHANNEL_INFO_BIN_DIMENSIONS, IPType, TERMINAL_PROTOCOL, DEFAULT_BAN_REASON, CHANNEL_BIN_INVALIDATE_DIMENSIONS,\
    RSA_KEY_SIZE, EULA_FILE
from channel.server.PublishChannelService import PublishChannelService
from channel.server.ServerAliveService import ServerAliveService
from channel.server.ServerConnectionService import ServerConnectionService
from channel.server.ServerHostService import ServerHostService
from channel.server.TerminalValidateService import TerminalValidateService
from channel.server.UnPublishChannelService import UnPublishChannelService
from utils.BinarySequencer import Bin, ArbitraryValue
from utils.Language import info
from utils.MessengerExceptions import ServerException


class Server:
    def __init__(self, paramServerTerminal: str, channel_id=None, secret_key=None, port=DEFAULT_PORT_SERVER,
                 tunnel_url=None, public=False, max_users=20, banned_users=None):

        # Check for eula variable
        if not readEULA():
            raise ServerException(None, ServerException.EULA_FALSE)

        # Validate that the server terminal starts with an accepted protocol
        if not any([paramServerTerminal.startswith(protocol) for protocol in TERMINAL_PROTOCOL]):
            raise ServerException(None, ServerException.INVALID_TERMINAL_URL)

        # Server address
        self.__terminal: str = paramServerTerminal
        self.__port: int = port
        self.__tunnelURL: dict | None = tunnel_url

        # Server Channel
        self.__channelID: str = channel_id if channel_id is not None else generateRandomChannelID()
        self.__secretKey: str = secret_key if secret_key is not None else generateRandomSecretKey()
        self.__public: bool = public

        # RSA
        self.__privateKey: RSAPrivateKey | None = None
        self.generatePublicAndPrivateKeys()

        # User Management
        self.__userList: list[ServerConnectionService] = []
        self.__bannedUsers: list[str] = [] if banned_users is None else banned_users
        self.__maxNumberOfUsers: int = max_users


        # Events
        self.__stop: Event = Event()
        self.__ready: Event = Event()

        # Services
        self.__serverHostService: ServerHostService | None = None
        self.__serverAliveService: ServerAliveService | None = None

        self.startServer()

    """
            Getter Methods
    """

    def getTerminal(self) -> str:
        """
        Returns the terminal being used
        :return: Terminal URL (str)
        """
        return self.__terminal

    def getChannelID(self) -> str:
        """
        Returns the channel ID of the server
        :return: Channel ID (str)
        """
        return self.__channelID

    def getSecretKey(self) -> str:
        """
        Returns the secret key of the server
        :return: Secret key of server (str)
        """
        return self.__secretKey

    def getPort(self) -> int:
        """
        Returns the server port
        :return: Server port (int)
        """
        return self.__port

    def isPublic(self) -> bool:
        """
        Returns if the server is shown as public on the terminal
        :return: Server shown (bool)
        """
        return self.__public

    """
                Events
    """

    def getReadyEvent(self) -> Event:
        """
        Returns the ready event
        :return: Stop flag (Event)
        """
        return self.__ready

    def getStopEvent(self) -> Event:
        """
        returns the flag for the server being stopped
        :return: Stop flag (Event)
        """
        return self.__stop

    """
                IP
    """

    @lru_cache(maxsize=1)
    def getIP(self) -> dict:
        """
        Returns the ip in all different forms
        :return:
        """

        response = requests.get("https://httpbin.org/ip")  # Makes a request to find the external ip

        if response.status_code != 200:  # Check that the request is OK
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_IP)

        ip = response.json()['origin']  # Read the IP from the website

        # Bundles up the ip

        # Check if IP is 0: v4 or 1: v6 and return it in binary
        if "." in ip:
            return {"internal_ip": '127.0.0.1',
                    "ip_type": IPType.IPv4,
                    "ip": ip,
                    "ip_binary": int(''.join([bin(int(split))[2:].zfill(8) for split in ip.split(".")]), 2)
                    }

        elif ":" in ip:
            return {"internal_ip": '127.0.0.1',
                    "ip_type": IPType.IPv6,
                    "ip": ip,
                    "ip_binary": int(''.join([bin(int(split, 16))[2:].zfill(16) for split in ip.split(":")]), 2)
                    }

    """
            Tunneling
    """

    def isTunneling(self) -> bool:
        """
        Returns if the server is tunneling
        :return: Server is tunneling (bool)
        """
        return self.__tunnelURL is not None

    def getTunnelURL(self) -> dict:
        """
        Returns the tunnel url
        :return: tunnel url {http(s)://..., port}
        """
        return self.__tunnelURL

    def setTunnelURL(self, paramTunnelURL: dict):
        """
        Sets the tunnel url
        :param paramTunnelURL: tunnel url {http(s)://..., port}
        :return:
        """
        self.__tunnelURL = paramTunnelURL

    """
            Services
    """

    def getServerHostService(self) -> ServerHostService:
        """
        Returns the host service
        :return: Host service
        """
        return self.__serverHostService

    def getServerAliveService(self) -> ServerAliveService:
        """
        Returns the alive service
        :return:
        """
        return self.__serverAliveService

    """
            Server Connection Service
    """

    def getUserByDisplayName(self, paramDisplayName: str) -> ServerConnectionService:
        """
        Gets the Server Connection Service by their display name
        :param paramDisplayName: Display name searched for
        :return: client connections
        """
        for serverConnectionService in self.getUserList():
            if serverConnectionService.getDisplayName(False) == paramDisplayName:
                return serverConnectionService

        raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_FIND_USER)

    def getMaxNumberOfUsers(self) -> int:
        """
        Returns the max number of users on the server
        :return: Max number of users on the server
        """
        return self.__maxNumberOfUsers

    def setMaxNumberOfUsers(self, paramNumberOfUsers) -> None:
        """
        Set the max number of users on the server
        :param paramNumberOfUsers: Max number of clients
        :return: None
        """
        self.__maxNumberOfUsers = paramNumberOfUsers

    def getUserList(self) -> list[ServerConnectionService]:
        """
        Returns the list of users on the server
        :return: List of server users
        """
        return self.__userList


    def getNumberOfUsers(self) -> int:
        """
        Gets the number of users
        :return: Number of users
        """
        return len(self.getUserList())

    def getBannedUsers(self) -> list[str]:
        """
        Returns a list of banned IPs
        :return:
        """
        return self.__bannedUsers

    def banUser(self, paramDisplayName: str, paramReason=DEFAULT_BAN_REASON):
        """
        Bans a user
        :param paramReason: Reason for ban
        :param paramDisplayName: Display name of user to ban
        """
        client = self.getUserByDisplayName(paramDisplayName)
        client.banUser(paramReason)

    def kickUser(self, paramDisplayName: str, paramReason: str):
        """
        Kicks a user from the server
        :param paramDisplayName: Display name of user to kick
        :param paramReason: Reason for kick
        :return:
        """
        client = self.getUserByDisplayName(paramDisplayName)
        client.kickUser(paramReason)

    def kickAllUsers(self, disconnect_reason=None):
        """
        Kicks all users from the server
        :param disconnect_reason:
        :return:
        """
        for key in self.getUserList()[:]:  # Duplicate user list to avoid problems
            key.kickUser(disconnect_reason)

    """
                RSA
    """

    def getServerPrivateKey(self) -> RSAPrivateKey:
        """
        Returns the Server Private Key
        :return: Server Private Key (RSAPrivateKey)
        """
        return self.__privateKey

    def getServerPublicKey(self) -> RSAPublicKey:
        """
        Returns the Server Public Key
        :return: Server Public Key
        """
        return self.getServerPrivateKey().public_key()

    def generatePublicAndPrivateKeys(self) -> None:
        """
        Generates the public and private keys
        :return: None
        """
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,  # The size of the key in bits
        )

        self.__privateKey = private_key

    """
                SERVER
    """

    def stopServer(self):
        # Start invalidate service in terminal
        unpublishService = UnPublishChannelService(self.getStopEvent(), self.getTerminal(),
                                                   createInvalidateChannelBin(self))
        unpublishService.start()

        # Kick all users
        self.kickAllUsers("Server stopping.")
        self.getStopEvent().set()

        self.getServerAliveService().join()
        self.getServerHostService().join()

        # Wait for the host service to finish
        info("CHANNEL_CLOSE", terminal=self.getTerminal(), channel_id=self.getChannelID(),
             secret_key=self.getSecretKey(), ip=self.getIP().get("ip"),
             port=str(self.getPort()), public=str(self.isPublic()))

        # Wait for all to finish
        unpublishService.join()
        if not unpublishService.getResult()['SUCCESS']:  # Check if successfully unpublished channel
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_UNPUBLISH_CHANNEL)


    def startServer(self):
        # 1) Check if terminal is available
        terminalValidateService = TerminalValidateService(self.getTerminal())
        terminalValidateService.start()
        terminalValidateService.join()

        if not terminalValidateService.getResult():
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_VALIDATE_TERMINAL)

        # 2) Start receiver thread

        serverHostService = ServerHostService(self.getPort(), self.getStopEvent(), self.getChannelID(),
                                              self.getServerPrivateKey(), self.getMaxNumberOfUsers(),
                                              self.getUserList(), self.getBannedUsers(), self.getSecretKey())

        serverHostService.start()  # Start the host service
        self.__serverHostService = serverHostService

        # Wait for it to start or if it doesnt then return an error
        while True:
            if serverHostService.getReadyEvent().is_set():
                break
            if self.getStopEvent().is_set():
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_START_HOST_SERVICE)

        # 2.1) Send message after service is ready
        info("CHANNEL_CREATE", terminal=self.getTerminal(), channel_id=self.getChannelID(),
             secret_key=self.getSecretKey(), ip=self.getIP().get("ip"),
             port=str(self.getPort()), public=str(self.isPublic()))

        # 3) Start alive service

        serverAliveService = ServerAliveService(self.getUserList(), self.getStopEvent())
        serverAliveService.start()
        self.__serverAliveService = serverAliveService

        # 4) Publish channel public service

        publishChannelService = PublishChannelService(self.getStopEvent(), self.getTerminal(), self.getChannelID(),
                                                      self.isPublic(), createValidateChannelBin(self))
        publishChannelService.start()
        publishChannelService.join()

        if not publishChannelService.getResult()['SUCCESS']:
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_PUBLISH_CHANNEL)


def readEULA() -> bool:
    """
    Returns the variable from the eula
    :return: EULA variable
    """

    # Check if eula file exists
    if not os.path.exists(EULA_FILE):
        raise ServerException(None, ServerException.EULA_DOES_NOT_EXIST)

    try:
        with open(EULA_FILE, "r") as file:

            file_content = file.read()

            # Use regex to see if the eula variable is set to true or false
            eula_status = re.search(r"eula\s*=\s*(?i)(true|false)", file_content)

            # Check if eula variable is found
            if eula_status:
                # Extract the status of eula variable
                eula_value = eula_status.group(1)

                if eula_value.lower() == "true":  # Check if eula is true
                    return True
                return False  # Anything else will return false
            else:
                raise ServerException(None, ServerException.NO_EULA_VARIABLE)
    except PermissionError:
        raise ServerException(None, ServerException.ERROR_OPENING_EULA)





def generateRandomSequence(length: tuple | int) -> str:
    """
    Generate a random sequence containing hyphens to split text
    :param length:
    :return:
    """
    if isinstance(length, tuple):
        length = random.randint(length[0],
                                length[1])

    assert isinstance(length, int)

    # Don't use " " or "-" from base64 alphabet for channel ID
    randomCharacterArray = random.choices(re.sub('[- ]', '', string.ascii_letters), k=length)
    numberOfHyphens = len(randomCharacterArray) // 4

    # Run through the string to insert hyphens
    for index in range(numberOfHyphens // 2):
        for hyphenLocation in [(index + 1) * numberOfHyphens,
                               len(randomCharacterArray) - ((index + 1) * numberOfHyphens)]:
            if not (index + 1) * numberOfHyphens:  # Avoid indexing 0
                continue

            if (hyphenLocation - 1 >= 0 and randomCharacterArray[hyphenLocation - 1] != '-') and \
                    (hyphenLocation + 1 < len(randomCharacterArray) and randomCharacterArray[
                        hyphenLocation + 1] != '-'):
                randomCharacterArray[hyphenLocation] = '-'

    return "".join(randomCharacterArray)


def generateRandomChannelID(length=CHANNEL_ID_LENGTH) -> str:
    """
    Generate a random channel ID
    :param length:
    :return:
    """
    return generateRandomSequence(length)


def generateRandomSecretKey(length=CHANNEL_SECRET_KEY_LENGTH) -> str:
    """
    Generate a random channel secret key
    :param length:
    :return:
    """
    return generateRandomSequence(length)


def xorRing(value0: int, value1: int) -> int:
    """
    XOR Ring two ints
    :param value0: int1
    :param value1: int2
    :return: xor result
    """
    return value0 ^ value1


def generateAuthenticationID(paramAuthSum) -> list[int]:
    """
    Generates an authentication sequence
    :param paramAuthSum:
    :return:
    """
    return [authCount := paramAuthSum - random.randint(0, paramAuthSum), paramAuthSum - authCount]


def createChannelInfoBin(paramServer: Server) -> Bin:
    """
    Creates the channel info bin
    :param paramServer: Server
    :return: Channel info bin
    """
    channelInfoBin = Bin(CHANNEL_INFO_BIN_DIMENSIONS)

    # UNIQUE AUTH
    authentication_sum = (2 ** ((channelInfoBin.getAttributeSize("UNIQUE_AUTH_HI")
                                 + channelInfoBin.getAttributeSize("UNIQUE_AUTH_LO"))
                                // 2)) - 1
    authentication_hi, authentication_lo = generateAuthenticationID(authentication_sum)

    channelInfoBin.setAttribute("UNIQUE_AUTH_HI", authentication_hi)
    channelInfoBin.setAttribute("UNIQUE_AUTH_LO", authentication_hi)

    ip_attribute_size = channelInfoBin.getAttributeSize("IP")

    if paramServer.isTunneling():

        channelInfoBin.setAttribute("IP_TYPE", 2)

        ip_length_bits = len(paramServer.getTunnelURL().get("tunnel_url")) * 8
        ip_length = ip_length_bits + (ip_length_bits % 8)

        assert ip_length <= ip_attribute_size

        placement = ip_attribute_size - ip_length
        channelInfoBin.setAttribute("IP_PLACEMENT", placement)

        ip_bin = Bin([("A", placement, ArbitraryValue.RANDOMISE),
                      ("IP", ip_length, paramServer.getTunnelURL().get("tunnel_binary"))])

    else:
        ip_data = paramServer.getIP()

        match ip_data.get("ip_type"):
            case IPType.IPv4:
                channelInfoBin.setAttribute("IP_TYPE", 0)

                placement = random.randint(0, ip_attribute_size - 32)

                ip_bin = Bin([("A", placement, ArbitraryValue.RANDOMISE),
                              ("IP", 32, ip_data.get("ip_binary")),
                              ("Z", ip_attribute_size - placement - 32, ArbitraryValue.RANDOMISE)])

            case IPType.IPv6:
                channelInfoBin.setAttribute("IP_TYPE", 1)

                placement = random.randint(0, ip_attribute_size - 128)
                channelInfoBin.setAttribute("IP_PLACEMENT", placement)

                ip_bin = Bin([("A", placement, ArbitraryValue.RANDOMISE),
                              ("IP", 128, ip_data.get("ip_binary")),
                              ("Z", ip_attribute_size - placement - 128, ArbitraryValue.RANDOMISE)])
            case _:
                raise ServerException(None, ServerException.INVALID_IP_FORMAT)

    channelInfoBin.setAttribute("IP_PLACEMENT", placement)

    assert ip_bin.getBinSize() == channelInfoBin.getAttributeSize("IP")
    channelInfoBin.setAttribute("IP", ip_bin.getResult())


    channelInfoBin.setAttribute("PORT", paramServer.getPort())

    return channelInfoBin


def createValidateChannelBin(paramServer: Server) -> Bin:
    """
    Creates the channel info bin and then adds xor rings
    :param paramServer:
    :return:
    """
    channelBin = Bin(CHANNEL_BIN_DIMENSIONS)

    # Channel Info Bin
    channelNameHash = hashlib.sha512(paramServer.getChannelID().encode()).hexdigest()
    channelInfoBinXOR = xorRing(int(channelNameHash, 16), createChannelInfoBin(paramServer).getResult())
    channelBin.setAttribute("CHANNEL_INFO_BIN", channelInfoBinXOR)

    # Channel Secret Bin
    secretKeyHash = hashlib.sha256(paramServer.getSecretKey().encode()).hexdigest()
    secretKey = int(secretKeyHash, 16)
    channelBin.setAttribute("CHANNEL_SECRET_BIN", secretKey)

    return channelBin


def createInvalidateChannelBin(paramServer: Server) -> Bin:
    """
    Creates the invalidate channel bin info
    :param paramServer:
    :return:
    """

    invalidateChannelBin = Bin(CHANNEL_BIN_INVALIDATE_DIMENSIONS)

    channelBin: Bin = createValidateChannelBin(paramServer)
    infoBin: Bin = Bin(CHANNEL_INFO_BIN_DIMENSIONS, population=channelBin.getAttribute("CHANNEL_INFO_BIN"))

    # Set secret key
    invalidateChannelBin.setAttribute("CHANNEL_SECRET_BIN", channelBin.getAttribute("CHANNEL_SECRET_BIN"))
    invalidateChannelBin.setAttribute("UNIQUE_AUTH_HI", infoBin.getAttribute("UNIQUE_AUTH_HI"))
    invalidateChannelBin.setAttribute("UNIQUE_AUTH_LO", infoBin.getAttribute("UNIQUE_AUTH_LO"))

    return invalidateChannelBin
