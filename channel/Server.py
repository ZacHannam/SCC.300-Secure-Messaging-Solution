import random
import re
import hashlib
from functools import lru_cache
import traceback
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import socket
import time
from enum import Enum, auto
import subprocess

from Properties import CHANNEL_ID_LENGTH, CHANNEL_SECRET_KEY_LENGTH, DEFAULT_PORT_SERVER, CHANNEL_BIN_DIMENSIONS, \
    CHANNEL_INFO_BIN_DIMENSIONS, CHANNEL_USER_DISPLAY_NAME_MAX, ALIVE_TIME, MAXIMUM_MESSAGE_SIZE
from utils.codecs.Base64 import BASE_64_ALPHABET, intToBase64
from services.terminal.TerminalValidateService import TerminalValidateService
import services.Service as Service
from utils.BinarySequencer import Bin, ArbitraryValue, getBinSize
from utils.codecs.Base85 import intToBase85
from channel.packet.Packet import sendPacket, PacketType, PacketCollector
from channel.packet.server.S2C_ChallengePacket import ServerChallengePacket
from channel.packet.server.S2C_RequestUserDataPacket import RequestUserData
from channel.packet.server.S2C_UserLeavePacket import UserLeavePacket
from channel.packet.server.S2C_UserJoinPacket import UserJoinPacket
from channel.packet.server.S2C_AlivePacket import AlivePacket
from channel.packet.server.S2C_InfoMessagePacket import InfoMessagePacket
from channel.packet.server.S2C_TextMessagePacket import TextMessagePacket
from Language import info


class IPType(Enum):
    IPv4   = auto()
    IPv6   = auto()


class User:
    def __init__(self, paramConnection, paramDisplayName: str,
                 paramPublicKey: RSAPublicKey, paramServerConnectionService):
        self.__connection = paramConnection
        self.__displayName = paramDisplayName
        self.__publicKey = paramPublicKey
        self.__lastAliveTime = int(time.time())
        self.__serverConnectionService = paramServerConnectionService

    def stop(self):
        self.__serverConnectionService.stop()
        self.getConnection().close()

    def getDisplayName(self) -> str:
        return self.__displayName

    def getConnection(self):
        return self.__connection

    def getPublicKey(self) -> RSAPublicKey:
        return self.__publicKey

    def getLastAliveTime(self) -> int:
        return self.__lastAliveTime

    def renewTime(self):
        self.__lastAliveTime = int(time.time())


class Server:
    def __init__(self, paramTerminal: str, channel_id=None, secret_key=None, port=DEFAULT_PORT_SERVER,
                 tunnel=True, public=False):
        self.__terminal = paramTerminal

        self.__channelID = channel_id if channel_id is not None else generateRandomChannelID()
        self.__secretKeyBin = secret_key if secret_key is not None else generateRandomSecretKey()
        self.__port = port
        self.__public = public
        self.__tunnel = tunnel

        self.__users = {}
        self.__ip = self.__getIP()
        self.__tunnelURL = None

        self.__generatePublicAndPrivateKeys()
        self.__startServer()

    """
            Getter Methods
    """

    def isTunneling(self) -> bool:
        return self.__tunnel

    def getTerminal(self) -> str:
        return self.__terminal

    def getChannelID(self) -> str:
        return self.__channelID

    def getSecretKey(self) -> str:
        return self.__secretKeyBin

    def getPort(self) -> int:
        return self.__port

    def isPublic(self) -> bool:
        return self.__public

    def getChannelIDHash(self) -> int:
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()
        return int(hex_digest, 16)

    """
                IP
    """

    @lru_cache(maxsize=1)
    def __getIP(self) -> dict | None:  # {type, ip, ip_bin}

        response = requests.get("https://httpbin.org/ip")

        if response.status_code != 200:  # Check that the request is OK
            return None

        ip = response.json()['origin']

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

    def getIP(self) -> dict:
        return self.__ip

    """
            Tunneling
    """

    def beginTunnelingService(self):
        ...

    def getTunnelURL(self) -> dict:
        return self.__tunnelURL

    def setTunnelURL(self, paramTunnelURL: dict):
        self.__tunnelURL = paramTunnelURL

    """
                RSA
    """

    def getPrivateKey(self) -> RSAPrivateKey:
        return self.__privateKey

    def getPublicKey(self) -> RSAPublicKey:
        return self.getPrivateKey().public_key()

    @lru_cache()
    def getPublicKeyBytes(self) -> bytes:
        public_key_der = self.getPublicKey().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key_der

    def __generatePublicAndPrivateKeys(self):
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # The size of the key in bits
        )

        self.__privateKey = private_key

    """
                SERVER USERS
    """

    def getUser(self, paramIP) -> User:
        return self.__users.get(paramIP, None)

    def getAllRecipients(self) -> list:
        return [(user.getConnection(), user.getPublicKey()) for user in self.__users.values()]

    def registerUser(self, paramConnection, paramDisplayName, paramPublicKey, paramAuthenticateService) -> User:
        user = User(paramConnection, paramDisplayName, paramPublicKey, paramAuthenticateService)
        self.__users[paramConnection] = user

        userJoinPacket = UserJoinPacket(paramDisplayName)
        sendPacket(userJoinPacket, self.getAllRecipients())

        return user

    def isUser(self, paramIP: tuple) -> bool:
        return paramIP in self.__users

    def unregisterUser(self, paramConnection):
        if paramConnection in self.__users.keys():

            userJoinPacket = UserLeavePacket(self.__users.get(paramConnection).getDisplayName())
            sendPacket(userJoinPacket, self.getAllRecipients())

            self.__users.get(paramConnection).stop()
            del self.__users[paramConnection]

    def getUsers(self) -> dict:
        return self.__users

    """
                SERVER
    """

    def __stopServer(self):
        ...

    def __startServer(self):
        # 1) Check if terminal is available
        terminalValidateService = TerminalValidateService(self.getTerminal())
        terminalValidateService.start()
        terminalValidateService.join()

        if not terminalValidateService.getResult():
            raise RuntimeError(f"Failed to validate terminal {self.getTerminal()}")

        # 2) Start receiver thread

        channelHostService = ServerHostService(self)
        channelHostService.start()

        while not channelHostService.isRunning():
            continue

        if self.isTunneling():
            tunnelService = TunnelService(self)
            tunnelService.start()

            while self.getTunnelURL() is None:
                continue

        # 3) Start alive service

        aliveService = AliveService(self)
        aliveService.start()

        # 4) Publish channel public service

        publishChannelService = PublishChannelService(self)
        publishChannelService.start()
        publishChannelService.join()

        if not publishChannelService.getResult()['SUCCESS']:
            self.__stopServer()
            raise RuntimeError(f"Failed to publish channel\n{publishChannelService.getResult()['EXCEPTION']}")


class TunnelService(Service.ServiceThread):
    def __init__(self, paramServer: Server):
        super().__init__(Service.ServiceType.SERVER_TUNNEL)

        self.__server = paramServer
        self.__tunnelEstablished = False

    def getServer(self) -> Server:
        return self.__server

    def run(self):


        info("CHANNEL_BEGIN_TUNNEL", channel_id=self.getServer().getChannelID())

        process = subprocess.Popen(f"pylt port {str(self.getServer().getPort())}", shell=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

        time.sleep(2)

        # Read output line by line as it becomes available
        for line in process.stdout:
            try:
                urlMatch = re.search(r"your url is: (https?://\S+)", line)
                if urlMatch:
                    url = urlMatch.group(1)
                    self.getServer().setTunnelURL({"tunnel_url": url,
                                                   "tunnel_binary": int.from_bytes(url.encode('utf-8'), byteorder="big")
                                                   })
                    info("CHANNEL_FINISH_TUNNEL", channel_id=self.getServer().getChannelID(), tunnel_url=url)
                    continue


                exceptionMatch = re.search(r"Error: (.+)", line)
                if exceptionMatch:
                    raise RuntimeError(f"Exception occurred when connecting to tunnel: {exceptionMatch.group(1)}")
            except AttributeError:
                raise RuntimeError("Something wrong happened when connecting to tunnel")

        process.wait()

        print("Finished tunneling service")


class AliveService(Service.ServiceThread):
    def __init__(self, paramServer: Server):
        super().__init__(Service.ServiceType.SERVER_ALIVE)

        self.__server = paramServer

    def getServer(self) -> Server:
        return self.__server

    def run(self):
        while True:

            currentTime = int(time.time())

            for user in self.getServer().getUsers().values():
                if user.getLastAliveTime() + (ALIVE_TIME * 2) < currentTime:
                    self.getServer().unregisterUser(user)

            sendPacket(AlivePacket(), self.getServer().getAllRecipients())

            time.sleep(ALIVE_TIME)


class PublishChannelService(Service.ServiceThread):
    def __init__(self, paramServer: Server):
        super().__init__(Service.ServiceType.SERVER_PUBLISH)

        self.__server = paramServer
        self.__result = None

    """
            Getter Methods
    """

    def getResult(self) -> dict:
        return self.__result

    def getServer(self) -> Server:
        return self.__server

    """
            Methods
    """

    def __publish(self) -> None | dict:

        channelInfoBin = createChannelInfoBin(self.getServer())
        channelBin = createChannelBin(self.getServer(), channelInfoBin)

        base85channelBin = intToBase85(channelBin.getResult(),
                                       nBytes=getBinSize(CHANNEL_BIN_DIMENSIONS) // 8)

        try:
            json = {
                "CHANNEL": base85channelBin,
                "CHANNEL_SECRET": self.getServer().getSecretKey()
            }

            if self.getServer().isPublic():
                json["CHANNEL_ID"] = self.getServer().getChannelID()

            response = requests.post(f"{self.getServer().getTerminal()}/validate", json=json)

            return response.json()

        except (requests.RequestException, requests.exceptions.ContentDecodingError):
            return None

    def run(self):
        self.__result = self.__publish()


class ServerHostService(Service.ServiceThread):
    def __init__(self, paramServer: Server):
        super().__init__(Service.ServiceType.SERVER_HOST)

        self.__server = paramServer
        self.__running = False

    def getServer(self) -> Server:
        return self.__server

    def isRunning(self) -> bool:
        return self.__running

    def run(self):
        host = self.getServer().getIP()['ip']
        port = self.getServer().getPort()


        if self.getServer().isTunneling():
            host = self.getServer().getIP()['internal_ip']

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))

            info("CHANNEL_CREATE", terminal=self.getServer().getTerminal(), channel_id=self.getServer().getChannelID(),
                 secret_key=self.getServer().getSecretKey(), ip=self.getServer().getIP().get("ip"),
                 port=str(self.getServer().getPort()), public=str(self.getServer().isPublic()))

            self.__running = True

            server_socket.listen()

            while True:
                # Accept new connection
                connection, client_address = server_socket.accept()

                serverAuthenticateService = ServerConnectionService(self.getServer(), client_address, connection)
                serverAuthenticateService.start()


class ServerConnectionService(Service.ServiceThread):
    def __init__(self, paramServer: Server, paramClientAddress: tuple, paramConnection):
        super().__init__(Service.ServiceType.SERVER_CONNECTION)

        self.__server = paramServer
        self.__connection = paramConnection
        self.__clientAddress = paramClientAddress

        self.__packetCollector = None
        self.__user = None

    def getServer(self) -> Server:
        return self.__server

    """
            Packet Methods
    """

    def getPacketCollector(self) -> PacketCollector:
        return self.__packetCollector

    def __setPacketCollector(self, paramPacketCollector: PacketCollector):
        self.__packetCollector = paramPacketCollector

    """
            User
    """

    def getUser(self) -> User:
        return self.__user

    def __setUser(self, paramUser: User):
        self.__user = paramUser

    """
            Connection Methods
    """

    def getClientAddress(self) -> tuple:
        return self.__clientAddress

    def getConnection(self):
        return self.__connection

    def sendInfoToUser(self, paramMessage: str):
        infoMessagePacket = InfoMessagePacket(paramMessage)
        sendPacket(infoMessagePacket, (self.getConnection(), self.getUser().getPublicKey()))

    def __challenge(self) -> RSAPublicKey | None:
        try:

            # Validate challenge
            challenge_packetType, challenge_packetBin = self.getPacketCollector()\
                .awaitPacket(packet_type=PacketType.C2S_CHALLENGE)

            if challenge_packetBin.getAttribute("CHANNEL_HASH") != self.getServer().getChannelIDHash():
                raise ValueError("Channel Hash invalid")

            der_key_size = challenge_packetBin.getAttribute("PUBLIC_KEY_LENGTH")
            der_key = challenge_packetBin.getAttribute("CLIENT_PUBLIC_KEY").to_bytes(der_key_size, byteorder="big")

            client_public_key = serialization.load_der_public_key(
                der_key,
                backend=default_backend())

            clientEncryptedChallenge = client_public_key.encrypt(
                challenge_packetBin.getAttributeBytes("CHALLENGE"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Send back challenge
            serverChallengePacket = ServerChallengePacket(self.getServer().getChannelID(),
                                                          self.getServer().getPublicKey(),
                                                          clientEncryptedChallenge)

            sendPacket(serverChallengePacket, (self.getConnection(), None))

            # Get registration packet
            challenge_return_packetType, challenge_return_packetBin = self.getPacketCollector()\
                .awaitPacket(packet_type=PacketType.C2S_CHALLENGE_RETURN)

            if challenge_return_packetBin.getAttribute("CHANNEL_HASH") != self.getServer().getChannelIDHash():
                raise ValueError("Channel Hash invalid")

            decryptedClientChallenge = self.getServer().getPrivateKey().decrypt(
                challenge_return_packetBin.getAttributeBytes("SIGNED_CHALLENGE"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            if decryptedClientChallenge != serverChallengePacket.getChallengeBytes():
                raise ValueError("Signed challenge is invalid")

            return client_public_key

        except (ValueError, socket.timeout, socket.error, ConnectionResetError, cryptography.exceptions.NotYetFinalized,
                cryptography.exceptions.InvalidKey, KeyError):
            return None

    def __getUserData(self, paramPublicKey: RSAPublicKey) -> str | None:
        try:
            # Send back challenge
            serverRequestUserData = RequestUserData()
            sendPacket(serverRequestUserData, (self.getConnection(), paramPublicKey))

            userData_packetType, userData_packetBin = self.getPacketCollector()\
                .awaitPacket(packet_type=PacketType.C2S_USER_DATA)

            if userData_packetType != PacketType.C2S_USER_DATA:
                raise ValueError("Packet ID invalid")

            displayNameLength = userData_packetBin.getAttribute("DISPLAY_NAME_LENGTH")
            displayName = intToBase64(userData_packetBin.getAttribute("DISPLAY_NAME"))

            return displayName[:min(displayNameLength, CHANNEL_USER_DISPLAY_NAME_MAX)]

        except (ValueError, socket.timeout, socket.error, ConnectionResetError):
            return None

    def __startListener(self):
        try:
            while True:

                packetType, packetBin = self.getPacketCollector().awaitPacket()

                match packetType:
                    case PacketType.C2S_ALIVE_RESPONSE:
                        self.getServer().getUser(self.getConnection()).renewTime()

                    case PacketType.C2S_TEXT_MESSAGE:
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")
                        if encodedMessage is None:
                            continue

                        message = encodedMessage.decode('utf-8')
                        if len(message) > MAXIMUM_MESSAGE_SIZE:
                            self.sendInfoToUser(f"Message exceeds maximum size of: {MAXIMUM_MESSAGE_SIZE}")
                            continue

                        textMessagePacket = TextMessagePacket(self.getUser().getDisplayName(), message)
                        sendPacket(textMessagePacket, self.getServer().getAllRecipients())




        except (ValueError, socket.timeout, socket.error, ConnectionResetError):
            return

    def run(self):
        try:
            packetCollector = PacketCollector(self.getConnection(), self.getServer().getPrivateKey())
            packetCollector.start()
            self.__setPacketCollector(packetCollector)

            publicKey = self.__challenge()

            if publicKey is None:
                return

            displayName = self.__getUserData(publicKey)

            if displayName is None:
                return

            # Save user
            user = self.getServer().registerUser(self.getConnection(), displayName, publicKey, self)
            self.__setUser(user)

            self.__startListener()

            self.getServer().unregisterUser(self.getConnection())

        except Exception:
            traceback.print_exc()


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
    randomCharacterArray = random.choices(re.sub('[- ]', '', BASE_64_ALPHABET), k=length)
    numberOfHyphens = len(randomCharacterArray) // 4

    # Make sure a hyphen is placed in the centre of the string if there are an odd amount of them
    if numberOfHyphens % 2 == 1:
        randomCharacterArray[len(randomCharacterArray) // 2] = '-'
        numberOfHyphens -= 1

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
    return value0 ^ value1


def generateAuthenticationID(paramAuthSum) -> list[int]:
    return [authCount := paramAuthSum - random.randint(0, paramAuthSum), paramAuthSum - authCount]


def createChannelInfoBin(paramServer: Server) -> Bin:
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

        assert paramServer.getTunnelURL() is not None

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
                raise ValueError("Invalid IP format")

    channelInfoBin.setAttribute("IP_PLACEMENT", placement)

    assert ip_bin.getBinSize() == channelInfoBin.getAttributeSize("IP")
    channelInfoBin.setAttribute("IP", ip_bin.getResult())


    channelInfoBin.setAttribute("PORT", paramServer.getPort())

    return channelInfoBin


def createChannelBin(paramServer: Server, paramChannelInfoBin: Bin) -> Bin:
    channelBin = Bin(CHANNEL_BIN_DIMENSIONS)

    # Channel Info Bin
    channelNameHash = hashlib.sha512(paramServer.getChannelID().encode()).hexdigest()
    channelInfoBinXOR = xorRing(int(channelNameHash, 16), paramChannelInfoBin.getResult())
    channelBin.setAttribute("CHANNEL_INFO_BIN", channelInfoBinXOR)

    # Channel Secret Bin
    secretKeyHash = hashlib.sha256(paramServer.getSecretKey().encode()).hexdigest()
    secretKey = int(secretKeyHash, 16)
    channelBin.setAttribute("CHANNEL_SECRET_BIN", secretKey)

    return channelBin