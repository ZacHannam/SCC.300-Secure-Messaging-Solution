import random

import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import socket
from threading import Event, Lock
import requests

from Properties import CHANNEL_USER_DISPLAY_NAME_MAX, NAMES_LIST_FILE, TERMINAL_PROTOCOL, CHANNEL_BIN_DIMENSIONS,\
    RSA_KEY_SIZE
from utils.BinarySequencer import Bin, getBinSize
from Properties import CHANNEL_INFO_BIN_DIMENSIONS
import services.Service as Service
from channel.packet.Packet import sendPacket, PacketType, PacketCollector
from channel.packet.client.C2S_AuthenticatePacket import ClientAuthenticatePacket
from channel.packet.client.C2S_ReturnAuthenticatePacket import ClientAuthenticateReturnPacket
from channel.packet.client.C2S_UserDataPacket import UserDataPacket
from channel.packet.client.C2S_AliveReturnPacket import AliveReturnPacket
from channel.packet.client.C2S_TextMessagePacket import TextMessagePacket
from channel.packet.client.C2S_UserLeavePacket import UserLeavePacket
from utils.codecs.Base85 import base85ToInt
from Language import info
from channel.MessengerExceptions import ClientException


class TerminalScanService(Service.ServiceThread):
    def __init__(self, paramTerminal: str, paramChannelID: str):
        """
        Scan the terminal to find channel bin
        :param paramTerminal: Terminal to scan
        :param paramChannelID: Channel to find
        """
        super().__init__(Service.ServiceType.TERMINAL_SCAN)

        self.__terminal: str = paramTerminal
        self.__channelID: str = paramChannelID

        self.__lock: Lock = Lock()
        self.__directoryEntries: list = []

        self.__result: list = []

    """
                GETTER
    """

    def getResult(self) -> Bin | None:
        """
        Get the result
        :return: result (Bin)
        """
        return None if not len(self.__result) else self.__result[0]

    def getLock(self) -> Lock:
        """
        Get threading lock
        :return: threading Lock (Lock)
        """
        return self.__lock

    def getTerminal(self) -> str:
        """
        Get terminal URL
        :return: terminal URL (str)
        """
        return self.__terminal

    def getChannelID(self) -> str:
        """
        Get the channel ID
        :return: channel ID (str)
        """
        return self.__channelID

    def getDirectoryEntries(self) -> list:
        """
        Get the directory entries
        :return:
        """
        return self.__directoryEntries

    """
                METHODS
    """

    def getAllDirectoryEntries(self):
        """
        Get all the directories on the terminal page
        :return:
        """
        response = requests.get(self.getTerminal())

        if response.status_code != 200:
            raise ClientException(None, ClientException.FAILED_VALIDATE_TERMINAL)


        try:
            self.__directoryEntries = [key for key in response.json().keys()]
        except requests.exceptions.ContentDecodingError:
            raise ClientException(None, ClientException.FAILED_VALIDATE_TERMINAL)

    def findChannelEntry(self, threads=12):
        """
        Find the channel entry by spawning search threads
        :param threads:
        :return:
        """

        numberOfThreads = min(threads, len(self.getDirectoryEntries()))

        entryScanners = [EntryScanService(self.getChannelID(), self.getLock(),
                                          self.getDirectoryEntries(), self.__result)
                         for _ in range(numberOfThreads)]

        for scanner in entryScanners:
            scanner.start()

        for scanner in entryScanners:
            scanner.join()

    def run_safe(self):
        self.getAllDirectoryEntries()
        self.findChannelEntry()


class EntryScanService(Service.ServiceThread):
    def __init__(self, paramChannelID: str, paramLock: Lock, paramDirectoryEntries: list, paramResult: list):
        super().__init__(Service.ServiceType.TERMINAL_SCAN_TH)

        self.__channelID: str = paramChannelID
        self.__lock: Lock = paramLock
        self.__directoryEntries: list = paramDirectoryEntries
        self.__result = paramResult

    def getChannelID(self) -> str:
        """
        Get the channel ID
        :return: channel ID (str)
        """
        return self.__channelID

    def getDirectoryEntries(self) -> list:
        """
        Get the directory entries
        :return:
        """
        return self.__directoryEntries

    def getLock(self) -> Lock:
        """
        Get the main lock
        :return: Terminal Scan lock
        """
        return self.__lock

    def getResult(self) -> list:
        """
        Get the result
        :return: Result
        """
        return self.__result

    def setResult(self, paramResult: Bin) -> None:
        """
        Set result value
        :param: The result info bin
        :return: None
        """
        self.__result.append(paramResult)

    def getNextDirectoryEntry(self) -> str | None:
        """
        Returns the next directory entry to scan
        :return:
        """
        with self.getLock():
            if len(self.getDirectoryEntries()) > 0 and not len(self.getResult()):
                return self.getDirectoryEntries().pop()
            return None

    def run_safe(self):
        while (entry := self.getNextDirectoryEntry()) is not None:
            intValueEntry = base85ToInt(entry)

            entry_bin = Bin(CHANNEL_BIN_DIMENSIONS, population=intValueEntry).getAttribute("CHANNEL_INFO_BIN")
            info_bin = Bin(CHANNEL_INFO_BIN_DIMENSIONS, population=entry_bin)

            # Reverse encryption
            info_hash = hashlib.sha512(self.getChannelID().encode()).hexdigest()

            info_bin.xor(int(info_hash, 16))

            assert getBinSize(CHANNEL_INFO_BIN_DIMENSIONS) == info_bin.getBinSize()

            bin_authorisation_lo, bin_authorisation_hi = info_bin.getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")
            if bin_authorisation_lo - bin_authorisation_hi == 0:  # Authorisation does not match
                self.setResult(info_bin)


class ClientConnectionService(Service.ServiceThread):
    def __init__(self, paramServerIP: str, paramServerPort: int, paramStopEvent: Event,
                 paramClientDisplayName: str, paramChannelID: str,
                 paramClientPrivateKey: RSAPrivateKey, paramServerPublicKey: RSAPublicKey):
        super().__init__(Service.ServiceType.CLIENT_CONNECTION)  # Establish the service thread

        self.__serverIP: str = paramServerIP
        self.__serverPort: int = paramServerPort
        self.__clientDisplayName: str = paramClientDisplayName
        self.__channelID: str = paramChannelID
        self.__clientPrivateKey: RSAPrivateKey = paramClientPrivateKey
        self.__serverPublicKey: RSAPublicKey = paramServerPublicKey


        self.__connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # Create a client socket

        self.__connection.connect((self.getServerIP(),          # Connect client socket to server
                                   self.getServerPort()))

        self.__stop = paramStopEvent    # Client stop flag
        self.__ready = Event()          # Client ready flag

        # Set the packet collector
        self.__packetCollector = PacketCollector(self.getConnection(), self.getClientPrivateKey(), self.getStopEvent())
        self.__packetCollector.start()


    """
            Getter and Setter Methods
    """

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

    def getChannelID(self) -> str:
        """
        returns the client / server channel id
        :return: Channel ID for server / client (str)
        """
        return self.__channelID

    def getChannelIDHash(self) -> int:
        """
        returns the sha256 version of the server channel id as an int
        :return: sha256(channelID) (base 10)
        """
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()  # Convert the channel id to sha256
        return int(hex_digest, 16)  # Returns the int conversion of the hex digest

    def getClientPrivateKey(self) -> RSAPrivateKey:
        """
        Returns the client private key (RSA)
        :return: Client Private Key (RSA)
        """
        return self.__clientPrivateKey

    def getClientPublicKey(self) -> RSAPublicKey:
        """
        Returns the client public key (RSA)
        :return: Client Public Key (RSA)
        """
        return self.__clientPrivateKey.public_key()

    def getServerPublicKey(self) -> RSAPublicKey:
        """
        Returns the server public key (RSA)
        :return: Server Public Key (RSA)
        """
        return self.__serverPublicKey


    def getReadyEvent(self) -> Event:
        """
        returns the flag for the client connection ready to send and receive packets
        :return: Ready flag (Event)
        """
        return self.__ready

    def getStopEvent(self) -> Event:
        """
        returns the flag for the client connection being stopped
        :return: Stop flag (Event)
        """
        return self.__stop

    """
            Packets
    """

    def sendPacket(self, paramPacket) -> None:
        """
        Send a packet to the server
        :param paramPacket: Packet to be sent to server
        :return: None
        """
        sendPacket(paramPacket, (self.getConnection(), self.getServerPublicKey()))  # send packet using Packet class

    def getPacketCollector(self) -> PacketCollector:
        """
        Get the packet collector
        :return: Packet collector for client
        """
        return self.__packetCollector


    """
            Connection Methods
    """

    def stop(self) -> None:
        """
        Stops the client connection to server and stops threads
        :return: None
        """
        userLeavePacket = UserLeavePacket()  # Constructs the user leave packet to server
        self.sendPacket(userLeavePacket)  # Sends the user leave packet to server

        self.__stop.set()  # Sets the stop flag so all threads close


    """
            Packet sending and receiving
    """

    def getConnection(self) -> socket.socket:
        """
        Returns the client socket
        :return: Client socket to server
        """
        return self.__connection

    def sendTextMessage(self, paramTextMessage) -> None:
        """
        Sends a text message to the server
        :param paramTextMessage: The text message to be sent
        :return: None
        """
        textMessagePacket = TextMessagePacket(paramTextMessage)  # Constructs the message packet
        self.sendPacket(textMessagePacket)  # Sends the text message packet


    def sendUserDataPacket(self) -> None:
        """
        Send the clients user data to the server
        :return: None
        """
        userDataPacket = UserDataPacket(self.getClientDisplayName())  # Construct the user data packet
        self.sendPacket(userDataPacket)  # Send the user data packet

    def authenticate(self) ->  None:
        """
        Authenticate the client with the server
        :return: None
        """

        try:
            """ 1) Client Authenticate Server """
            # 1.1) Send the client authentication packet to the server
            clientAuthenticatePacket = ClientAuthenticatePacket(self.getChannelID(),
                                                                self.getClientPublicKey())

            sendPacket(clientAuthenticatePacket, (self.getConnection(), None))

            """ 2) Server Authenticate Client """
            # 2.1) Validate the server challenge
            authenticatePacket = self.getPacketCollector().awaitPacket(PacketType.S2C_AUTHENTICATE)  # Collect packet
            if self.getStopEvent().is_set():
                return
            if authenticatePacket is None:  # Check if the packet is None
                raise ClientException(self.getStopEvent(), ClientException.FAILED_TO_COLLECT_PACKET)

            authenticate_packetType, authenticate_packetBin = authenticatePacket  # Unpack the packet

            # 2.2) Check the channel ID hash
            if authenticate_packetBin.getAttribute("CHANNEL_HASH") != self.getChannelIDHash():
                raise ClientException(self.getStopEvent(), ClientException.INVALID_CHANNEL_ID_HASH)

            # 2.3) Decrypt the client challenge sent to server and sent back encrypted
            decryptedClientChallenge = self.getClientPrivateKey().decrypt(
                authenticate_packetBin.getAttributeBytes("SIGNED_CHALLENGE"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 2.4) Check if the decrypted challenge is the same as the sent challenge
            if decryptedClientChallenge != clientAuthenticatePacket.getChallenge():
                raise ClientException(self.getStopEvent(), ClientException.SERVER_FAILED_CHALLENGE)

            # 2.5) Load the server public key
            der_key_size = authenticate_packetBin.getAttribute("PUBLIC_KEY_LENGTH")
            der_key = authenticate_packetBin.getAttribute("SERVER_PUBLIC_KEY").to_bytes(der_key_size, byteorder="big")

            server_public_key = serialization.load_der_public_key(
                der_key,
                backend=default_backend())

            self.__serverPublicKey = server_public_key  # Set the server public key

            """ 3) Client Authenticate Server Response """
            # 3.1) Encrypt the server challenge to send it back
            encryptedServerChallenge = server_public_key.encrypt(
                authenticate_packetBin.getAttributeBytes("CHALLENGE") + self.getChannelID().encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 3.2) Construct the response packet
            clientAuthenticateResponsePacket = ClientAuthenticateReturnPacket(self.getChannelID(),
                                                                              encryptedServerChallenge)
            # 3.3) Send the client authenticate response packet
            sendPacket(clientAuthenticateResponsePacket, (self.getConnection(), None))

        except (cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
            raise ClientException(self.getStopEvent(), ClientException.CRYPTOGRAPHY_EXCEPTION)

        except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
            raise ClientException(self.getStopEvent(), ClientException.SOCKET_EXCEPTION)

        except Exception:  # If any exception happens that can't be accounted for
            raise ClientException(self.getStopEvent(), ClientException.FAILED_TO_AUTHENTICATE)

    def startListener(self):
        """
        Start the listener for packets from the server
        :return: None
        """
        while not self.getStopEvent().is_set():  # Continue while the stop signal is not set
            try:
                packet = self.getPacketCollector().awaitPacket()  # Await for a packet from the packet collector
                if self.getStopEvent().is_set():
                    return

                if packet is None:
                    raise ClientException(self.getStopEvent(), ClientException.FAILED_TO_COLLECT_PACKET)

                packetType, packetBin = packet  # Unpack the packet

                match packetType:  # Match the packet type
                    case PacketType.S2C_REQUEST_USER_DATA:  # Wait for the request user data packet
                        self.sendUserDataPacket()  # Send the user data packet

                    case PacketType.S2C_CLIENT_DISCONNECT:  # Wait for the disconnect packet
                        info("CHANNEL_CLIENT_DISCONNECT", channel_id=self.getChannelID())  # Send disconnect message

                        encodedReason = packetBin.getAttributeBytes("REASON")  # Get the disconnect reason
                        if not (encodedReason is None or len(encodedReason) == 0):  # Check that there is a reason
                            reason = encodedReason.decode()  # Decode the reason
                            info("CHANNEL_CLIENT_DISCONNECT_REASON", channel_id=self.getChannelID(),
                                 reason=reason)  # Send the disconnect reason message

                        return  # User has been disconnect so return

                    case PacketType.S2C_USER_JOIN:  # Wait for a user disconnect packet

                        encodedDisplayName = packetBin.getAttributeBytes("DISPLAY_NAME")  # Get the display name
                        if not (encodedDisplayName is None or len(encodedDisplayName) == 0):
                            displayName = encodedDisplayName.decode()
                            info("CHANNEL_USER_JOIN", channel_id=self.getChannelID(),  # Send the user join message
                                 display_name=displayName)

                    case PacketType.S2C_USER_LEAVE:  # Wait for the user leave packet

                        encodedDisplayName = packetBin.getAttributeBytes("DISPLAY_NAME")  # Get the display name
                        if not (encodedDisplayName is None or len(encodedDisplayName) == 0):
                            displayName = encodedDisplayName.decode()
                            info("CHANNEL_USER_LEAVE", channel_id=self.getChannelID(),  # Send the user leave message
                                 display_name=displayName)

                    case PacketType.S2C_ALIVE:  # Wait for a user alive packet
                        self.sendPacket(AliveReturnPacket())  # Return the alive packet

                    case PacketType.S2C_INFO_MESSAGE:  # Wait for an info message from the server
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")  # Get the encoded message
                        if encodedMessage is None or len(encodedMessage) == 0:  # Check the info message is not empty
                            continue

                        message = encodedMessage.decode()  # Decode the message
                        info("CHANNEL_INFO", channel_id=self.getChannelID(),  # Send the info message
                             message=message)

                    case PacketType.S2C_TEXT_MESSAGE:  # Wait for a text message
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")  # Get the message
                        encodedDisplayName = packetBin.getAttributeBytes("DISPLAY_NAME")  # Get the display name
                        if encodedMessage is None or len(encodedMessage) == 0:  # Check the message is not empty
                            continue

                        if encodedDisplayName is None or len(encodedDisplayName) == 0:  # Check the display name
                            continue

                        message = encodedMessage.decode()  # Decode the message
                        displayName = encodedDisplayName.decode()  # Decode the display name

                        info("CHANNEL_TEXT_MESSAGE", channel_id=self.getChannelID(),  # Output the message
                             display_name=displayName, message=message)

            except (cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
                raise ClientException(self.getStopEvent(), ClientException.CRYPTOGRAPHY_EXCEPTION)

            except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
                raise ClientException(self.getStopEvent(), ClientException.SOCKET_EXCEPTION)

    def run_safe(self):
        try:
            # 1) Authenticate server
            self.authenticate()
            if self.getServerPublicKey() is None:
                raise ClientException(self.getStopEvent(), ClientException.FAILED_TO_GET_SERVER_PUBLIC_KEY)

            # 2) Set ready to listen
            self.getReadyEvent().set()

            # 3) Start packet listener
            self.startListener()

        finally:
            # 4) Close socket
            self.getStopEvent().set()
            self.getConnection().close()


class Client:
    def __init__(self, paramServerTerminal: str, paramChannelID: str, paramServerIP: str, paramServerPort: int,
                 client_displayName=None):
        """
        A client that connects to a server
        :param paramServerTerminal: Server Terminal URL
        :param paramChannelID: Channel ID of the Server
        :param paramServerIP: IP of the Server
        :param paramServerPort: Server Port
        :param client_displayName: Connection display name
        """

        # Validate that the server terminal starts with an accepted protocol
        if not any([paramServerTerminal.startswith(protocol) for protocol in TERMINAL_PROTOCOL]):
            raise ClientException(None, ClientException.INVALID_TERMINAL_URL)

        self.__serverTerminal: str = paramServerTerminal  # Server Terminal URL
        self.__serverIP: str = paramServerIP              # Server IP (x.x.x.x / a:a:a:a:a:a:a:a / http(s)://...)
        self.__serverPort: int = paramServerPort          # Server Port
        self.__channelID: str = paramChannelID            # Server Channel Name/ID

        # Generate a display name or generate one
        self.__clientDisplayName = client_displayName if client_displayName is not None else generateDisplayName()

        self.__privateKey: RSAPrivateKey = generatePrivateKey()   # Create private and public RSA key for client

        self.__stop = Event()       # Stop Event

        self.__serverPublicKey = None                   # Store the server public key
        self.__clientConnectService = None              # The client's connection to the server thread

        # Connect to the server
        self.__connectToServer()
    """
            Getter Methods
    """

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

    def sendMessage(self, paramMessage) -> None:
        """
        Send a message to the server in the form of text
        :param paramMessage: Message sent to other clients and server
        :return: None
        """
        self.getClientConnection().sendTextMessage(paramMessage)  # Send message through connection

    """
            CONNECT
    """

    def getClientConnection(self) -> ClientConnectionService:
        """
        Returns the client connection
        :return: Client socket to server
        """
        return self.__clientConnectService

    def __connectToServer(self) -> None:
        """
        Establish socket with the server
        :return: None
        """

        # Start the client connection service
        clientConnectService = ClientConnectionService(self.getServerIP(), self.getServerPort(), self.getStopEvent(),
                                                       self.getClientDisplayName(), self.getChannelID(),
                                                       self.getPrivateKey(), self.getServerPublicKey())
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

        selectName = lambda : names[random.randint(0, len(names))]  # Select a random name / line
        while (selectedName := selectName()) in ("", None):  # Make sure the name selected is not empty (double check)
            continue

    selectedName += "".join(random.choices("0123456789", k=random.randint(0, 3)))  # Add numbers to the end of the name

    assert selectedName[:max_length] not in (None, "")  # Assert that the name is not empty of null

    return selectedName[:max_length]  # Return the name selected up to the max size


def getClientFromBin(paramTerminal: str, paramChannelID: str, paramBin: Bin,
                     client_displayName=None) -> Client:
    """
    Create a client object from the client binary sequencer
    :param paramTerminal: The terminal URL
    :param paramChannelID: The channel ID
    :param paramBin: The client info bin
    :param client_displayName: The client display name
    :return: Client generated
    """

    assert getBinSize(CHANNEL_INFO_BIN_DIMENSIONS) == paramBin.getBinSize()  # Assert that the bin sizes matches

    # 1) Check if the authorisation matches
    bin_authorisation_lo, bin_authorisation_hi = paramBin.getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")
    if not bin_authorisation_lo - bin_authorisation_hi == 0:  # Authorisation does not match
        raise ClientException(None, ClientException.FAILED_TO_CREATE_CLIENT_FROM_BIN)

    # 2) Get the IP from the bin
    ip_type, ip_placement, ip  = paramBin.getAttribute("IP_TYPE", "IP_PLACEMENT", "IP")

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
    return Client(paramTerminal, paramChannelID, ip, port, client_displayName=client_displayName)


def getClientFromTerminalScan(paramTerminal: str, paramChannelID: str, client_displayName=None) -> Client:
    """
    Run a terminal scan to find the desired server and create a user from it
    :param paramTerminal: The Terminal to scan
    :param paramChannelID: The channel id to search for
    :param client_displayName: The display name to generate
    :return: Client generated from scan
    """
    terminalScanService = TerminalScanService(paramTerminal, paramChannelID)  # Start the terminal scan service
    terminalScanService.start()
    terminalScanService.join()  # Wait for it to gather a result

    if terminalScanService.getResult() is None:  # Check that it got a valid result
        raise ClientException(None, ClientException.NO_CHANNEL_ON_TERMINAL)

    return getClientFromBin(paramTerminal, paramChannelID, terminalScanService.getResult(),
                            client_displayName=client_displayName)  # Creates a client from the collected information