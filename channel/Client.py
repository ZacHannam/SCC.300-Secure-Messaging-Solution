import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import socket
import traceback

from Properties import CHANNEL_USER_DISPLAY_NAME_MAX, NAMES_LIST_FILE
from utils.codecs.Base64 import BASE_64_ALPHABET
from utils.BinarySequencer import Bin, getBinSize
from Properties import CHANNEL_INFO_BIN_DIMENSIONS
import services.Service as Service
from utils.codecs.Base64 import intToBase64
from channel.packet.Packet import sendPacket, PacketType, PacketCollector
from channel.packet.client.C2S_ChallengePacket import ClientChallengePacket
from channel.packet.client.C2S_ReturnChallengePacket import ClientChallengeReturnPacket
from channel.packet.client.C2S_UserDataPacket import UserDataPacket
from channel.packet.client.C2S_AliveReturnPacket import AliveReturnPacket
from channel.packet.client.C2S_TextMessagePacket import TextMessagePacket
from Language import info



class Client:
    def __init__(self, paramServerTerminal: str, paramChannelID: str, paramServerIP: str, paramServerPort: int,
                 client_displayName=None):
        self.__serverTerminal = paramServerTerminal
        self.__serverIP = paramServerIP
        self.__serverPort = paramServerPort
        self.__channelID = paramChannelID

        self.__clientDisplayName = client_displayName if client_displayName is not None else generateDisplayName()

        self.__generatePublicAndPrivateKeys()
        self.__serverPublicKey = None
        self.__clientConnectService = None

        self.__connectToServer()
    """
            Getter Methods
    """

    def getChannelID(self) -> str:
        return self.__channelID

    def getChannelIDHash(self) -> int:
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()
        return int(hex_digest, 16)

    def getServerTerminal(self) -> str:
        return self.__serverTerminal

    def getServerIP(self) -> str:
        return self.__serverIP

    def getServerPort(self) -> int:
        return self.__serverPort

    def getClientDisplayName(self) -> str:
        return self.__clientDisplayName

    """
            RSA
    """

    def getPrivateKey(self) -> RSAPrivateKey:
        return self.__privateKey

    def getPublicKey(self) -> RSAPublicKey:
        return self.getPrivateKey().public_key()

    def __generatePublicAndPrivateKeys(self):
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # The size of the key in bits
        )

        self.__privateKey = private_key

    """
            SERVER
    """

    def setServerPublicKey(self, paramPublicKey: RSAPublicKey):
        self.__serverPublicKey = paramPublicKey

    def getServerPublicKey(self) -> RSAPublicKey:
        return self.__serverPublicKey

    def sendMessage(self, paramMessage):
        self.getClientConnection().sendTextMessage(paramMessage)

    """
            CONNECT
    """

    def getClientConnection(self):
        return self.__clientConnectService

    def __connectToServer(self):

        self.__clientConnectService = ClientConnectionService(self)
        self.__clientConnectService.start()


class ClientConnectionService(Service.ServiceThread):
    def __init__(self, paramClient: Client):
        super().__init__(Service.ServiceType.CLIENT_CONNECTION)

        self.__client = paramClient
        self.__connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.__connection.connect((self.getClient().getServerIP(), self.getClient().getServerPort()))
        self.__packetCollector = None

    def getClient(self) -> Client:
        return self.__client

    """
            Packets
    """

    def sendPacket(self, paramPacket):
        sendPacket(paramPacket, (self.getConnection(), self.getClient().getServerPublicKey()))


    def getPacketCollector(self) -> PacketCollector:
        return self.__packetCollector

    def __setPacketCollector(self, paramPacketCollector):
        self.__packetCollector = paramPacketCollector

    """
            Connection Methods
    """

    def getConnection(self):
        return self.__connection


    def __sendUserDataPacket(self):
        userDataPacket = UserDataPacket(self.getClient().getClientDisplayName())
        self.sendPacket(userDataPacket)

    def sendTextMessage(self, paramTextMessage):
        textMessagePacket = TextMessagePacket(paramTextMessage)
        self.sendPacket(textMessagePacket)

    def __challenge(self) -> RSAPublicKey:
        # Send authentication packet

        clientChallengePacket = ClientChallengePacket(self.getClient().getChannelID(),
                                                      self.getClient().getPublicKey())

        sendPacket(clientChallengePacket, (self.getConnection(), None))

        # Validate challenge
        challenge_packetType, challenge_packetBin = self.getPacketCollector().awaitPacket(PacketType.S2C_CHALLENGE)

        if challenge_packetBin.getAttribute("CHANNEL_HASH") != self.getClient().getChannelIDHash():
            raise ValueError("Channel Hash invalid")

        decryptedClientChallenge = self.getClient().getPrivateKey().decrypt(
            challenge_packetBin.getAttributeBytes("SIGNED_CHALLENGE"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if decryptedClientChallenge != clientChallengePacket.getChallengeBytes():
            raise ValueError("Signed challenge is invalid")

        der_key_size = challenge_packetBin.getAttribute("PUBLIC_KEY_LENGTH")
        der_key = challenge_packetBin.getAttribute("SERVER_PUBLIC_KEY").to_bytes(der_key_size, byteorder="big")

        server_public_key = serialization.load_der_public_key(
            der_key,
            backend=default_backend())

        # Send back challenge

        encryptedServerChallenge = server_public_key.encrypt(
            challenge_packetBin.getAttributeBytes("CHALLENGE"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        clientChallengeResponsePacket = ClientChallengeReturnPacket(self.getClient().getChannelID(),
                                                                    encryptedServerChallenge)

        sendPacket(clientChallengeResponsePacket, (self.getConnection(), None))

        # Finish and save the data gathered to the client
        return server_public_key

    def __startListener(self):
        try:
            while True:

                packetType, packetBin =  self.getPacketCollector().awaitPacket()

                match packetType:
                    case PacketType.S2C_REQUEST_USER_DATA:
                        self.__sendUserDataPacket()

                    case PacketType.S2C_USER_JOIN:

                        displayNameLength = packetBin.getAttribute("DISPLAY_NAME_LENGTH")
                        displayName = intToBase64(packetBin.getAttribute("DISPLAY_NAME"))

                        info("CHANNEL_USER_JOIN", channel_id=self.getClient().getChannelID(),
                             display_name=displayName[:displayNameLength])

                    case PacketType.S2C_USER_LEAVE:

                        displayNameLength = packetBin.getAttribute("DISPLAY_NAME_LENGTH")
                        displayName = intToBase64(packetBin.getAttribute("DISPLAY_NAME"))

                        info("CHANNEL_USER_LEAVE", channel_id=self.getClient().getChannelID(),
                             display_name=displayName[:displayNameLength])

                    case PacketType.S2C_ALIVE:
                        self.sendPacket(AliveReturnPacket())

                    case PacketType.S2C_INFO_MESSAGE:
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")
                        if encodedMessage is None or len(encodedMessage) == 0:
                            continue

                        message = encodedMessage.decode()
                        info("CHANNEL_INFO", channel_id=self.getClient().getChannelID(),
                             message=message)

                    case PacketType.S2C_TEXT_MESSAGE:
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")
                        if encodedMessage is None or len(encodedMessage) == 0:
                            continue

                        message = encodedMessage.decode()
                        displayName = intToBase64(packetBin.getAttribute("DISPLAY_NAME"))
                        info("CHANNEL_TEXT_MESSAGE", channel_id=self.getClient().getChannelID(),
                             display_name=displayName, message=message)


        except (ValueError, socket.timeout, socket.error, ConnectionResetError):
            return

    def run(self):
        try:
            packetCollector = PacketCollector(self.getConnection(), self.getClient().getPrivateKey())
            packetCollector.start()
            self.__setPacketCollector(packetCollector)


            self.getClient().setServerPublicKey(self.__challenge())

            self.__startListener()

            self.getConnection().close()

        except Exception:
            traceback.print_exc()


def generateDisplayName(max_length=CHANNEL_USER_DISPLAY_NAME_MAX) -> str:

    with open(NAMES_LIST_FILE) as nameFile:
        names = nameFile.readlines()
        selectedName = names[random.randint(0, len(names))]

    selectedName = "".join([char for char in selectedName if char in BASE_64_ALPHABET])
    selectedName += "".join(random.choices("0123456789", k=random.randint(0, 3)))

    return selectedName[:max_length]


def getClientFromBin(paramTerminal: str, paramChannelID: str, paramBin: Bin,
                     client_displayName=None) -> None | Client:

    assert getBinSize(CHANNEL_INFO_BIN_DIMENSIONS) == paramBin.getBinSize()

    # Check if the authorisation matches

    bin_authorisation_lo, bin_authorisation_hi = paramBin.getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")

    if not bin_authorisation_lo - bin_authorisation_hi == 0:  # Authorisation does not match
        return None

    ip_type, ip_placement, ip  = paramBin.getAttribute("IP_TYPE", "IP_PLACEMENT", "IP")

    ip_size = 0
    match ip_type:
        case 0:
            ip_size = 32
        case 1:
            ip_size = 128
        case 2:
            ip_size = ip_placement

    ip_bin = Bin([("A", ip_placement),
                  ("IP", ip_size),
                  ("Z", paramBin.getAttributeSize("IP") - ip_placement - ip_size)], population=ip)

    assert isinstance(ip_bin.getAttribute("IP"), int)

    match ip_type:
        case 0:  # IPv4

            ip = ".".join([str(n) for n in list(ip_bin.getAttribute("IP").to_bytes(4, byteorder="big", signed=False))])
        case 1:  # Ipv4

            ip_bin = Bin([(c, 16) for c in 'ABCDEFGH'], population=ip_bin.getAttribute("IP"))
            ip = ":".join([hex(r) for r in ip_bin.getAttribute('A', 'B', 'C', 'D', 'E', 'F', 'G')])
        case 2:

            ip_bin = Bin([("A", ip_size),
                          ("IP", paramBin.getAttributeSize("IP") - ip_size)], population=ip)

            ip = ip_bin.getAttributeBytes("IP").decode('utf-8')
        case _:
            raise RuntimeError("Should not reach here")

    port = paramBin.getAttribute("PORT")

    print(paramTerminal, paramChannelID, ip, port)

    return Client(paramTerminal, paramChannelID, ip, port, client_displayName=client_displayName)
