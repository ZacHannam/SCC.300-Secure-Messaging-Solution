import hashlib
import hmac
import socket
import string
import time
import types
from threading import Event
from typing import Any, Optional

import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding

from Properties import LEGAL_DISPLAY_NAME_CHARACTERS, CHANNEL_USER_DISPLAY_NAME_MAX, MAXIMUM_MESSAGE_SIZE, \
    MAX_FILE_SIZE_BYTES
from channel.server.packet.S2C_FileSendPacket import FileSendPacket
from channel.server.packet.S2C_ServerReceivedFile import ServerReceivedFile
from utils.MessengerExceptions import ServerException
from channel.Packet import PacketCollector, Packet, sendPacket, PacketType
from channel.server.packet.S2C_AuthenticatePacket import ServerAuthenticatePacket
from channel.server.packet.S2C_ClientDisconnectPacket import ClientDisconnectPacket
from channel.server.packet.S2C_InfoMessagePacket import InfoMessagePacket
from channel.server.packet.S2C_RequestUserDataPacket import RequestUserData
from channel.server.packet.S2C_TextMessagePacket import TextMessagePacket
from channel.server.packet.S2C_UserJoinPacket import UserJoinPacket
from channel.server.packet.S2C_UserLeavePacket import UserLeavePacket
from channel import Service


class ServerConnectionService(Service.ServiceThread):
    def __init__(self, paramClientAddress: tuple, paramConnection: socket.socket, paramChannelID: str,
                 paramServerPrivateKey: RSAPrivateKey, paramServerMaxUsers: int, paramServerUserList: list,
                 paramServerBanList: list, paramServerSecret: str):
        """
        Connect the client service
        :param paramClientAddress: (ip, port)
        :param paramConnection: Connection socket
        """
        super().__init__(Service.ServiceType.SERVER_CONNECTION)

        # General Server / User information
        self.__connection: socket.socket = paramConnection  # Socket connecting to client
        self.__clientAddress: tuple = paramClientAddress  # Client address (ip, port)
        self.__channelID: str = paramChannelID  # Channel ID
        self.__serverPrivateKey: RSAPrivateKey = paramServerPrivateKey  # Server Private Key
        self.__lastAliveTime: int = int(time.time())  # Last time client was alive
        self.__serverSecret: str = paramServerSecret

        # Obtained client information
        self.__displayName: str | None = None  # Client display name
        self.__clientPublicKey: RSAPublicKey | None = None  # Client public key
        self.__adminPermission: bool = False  # If the client is an admin
        self.__receiveFiles: bool = False  # If the client receives files

        # Service flags
        self.__stop = Event()  # Stop event
        self.__ready = Event()  # Ready Event

        # Packet collector
        self.__packetCollector = PacketCollector(self.getConnection(), self.getServerPrivateKey(), self.getStopEvent())
        self.__packetCollector.start()

        # For server Authentication
        self.__serverMaxUsers: int = paramServerMaxUsers  # Max number of users on the server
        self.__serverUserList: list[ServerConnectionService] = paramServerUserList  # List of of users on the server
        self.__serverBanList: list[str] = paramServerBanList  # List of banned users on the server

    """
            Getter Methods
    """

    def getServerSecret(self) -> str:
        """
        Get the server secret
        :return: Server secret (str)
        """
        return self.__serverSecret

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

    def getReceiveFiles(self) -> bool:
        """
        Check if the client receives files
        :return:
        """
        return self.__receiveFiles

    def setReceivesFiles(self, paramReceivesFiles: bool) -> None:
        """
        Set if the user receives files
        :param paramReceivesFiles: if the user receives files
        :return: None
        """
        self.__receiveFiles = paramReceivesFiles

    def getAdminPermission(self) -> bool:
        """
        Check if the admin permission is true
        :return:
        """
        return self.__adminPermission

    def setAdminPermission(self, paramAdminPermission: bool) -> None:
        """
        Set admin status
        :param paramAdminPermission: bool
        :return: None
        """
        self.__adminPermission = paramAdminPermission

    """
            RSA
    """

    def getServerPrivateKey(self) -> RSAPrivateKey:
        """
        Get the server private key
        :return: The server private key (RSAPrivateKey)
        """
        return self.__serverPrivateKey

    def getServerPublicKey(self) -> RSAPublicKey:
        """
        Get the server public key
        :return: Server public key (RSAPublicKey)
        """
        return self.getServerPrivateKey().public_key()

    def setClientPublicKey(self, paramClientPublicKey: RSAPublicKey) -> None:
        """
        Set the client public key
        :param paramClientPublicKey: Client public key
        :return: None
        """
        self.__clientPublicKey = paramClientPublicKey

    def getClientPublicKey(self) -> RSAPublicKey:
        """
        Get the client's public key
        :return: The client's public key
        """
        return self.__clientPublicKey

    """
            Event Methods
    """

    def getReadyEvent(self) -> Event:
        """
        Returns the ready event
        :return:
        """
        return self.__ready

    def getStopEvent(self) -> Event:
        """
        returns the flag for the server connection being stopped
        :return: Stop flag (Event)
        """
        return self.__stop

    def stop(self) -> None:
        """
        Set the stop event
        :return: None
        """
        self.getStopEvent().set()

    """
            User
    """

    def registerUser(self) -> None:
        """
        Register as a user
        :return: None
        """
        assert self.getReadyEvent().is_set()

        self.getServerUserList().append(self)

        userJoinPacket = UserJoinPacket(self.getDisplayName(True))
        self.sendToAllRecipients(userJoinPacket)

    def unregisterUser(self) -> None:
        """
        Unregister as a user
        :return: None
        """
        self.getStopEvent().set()  # Set the stop flag
        if self in self.getServerUserList():  # Make sure the user is registered
            self.getServerUserList().remove(self)

            userLeavePacket = UserLeavePacket(self.getDisplayName(True))
            self.sendToAllRecipients(userLeavePacket)

    def setDisplayName(self, paramDisplayName: str) -> None:
        """
        Set the display name of the client
        :return: None
        """
        self.__displayName = paramDisplayName

    def getDisplayName(self, paramIncludeLevel) -> str:
        """
        Get the display name of the client
        :return: User display name (str)
        """
        return f"{self.__displayName}: Admin" if (self.getAdminPermission() and paramIncludeLevel) \
            else self.__displayName

    def getLastAliveTime(self) -> int:
        """
        Last time an alive signal was received from the client
        :return: Unix time (s)
        """
        return self.__lastAliveTime

    def renewTime(self) -> None:
        """
        Renews the time on the last alive time
        :return: None
        """
        self.__lastAliveTime = int(time.time())

    """
            Ban & Kick
    """

    def kickUser(self, paramReason: str | None) -> None:
        """
        Kicks user for specified reason or none
        :param paramReason: reason for kick
        :return: None
        """
        # Disconnect User
        clientDisconnectPacket = ClientDisconnectPacket(paramReason)
        self.sendPacket(clientDisconnectPacket)

        # Stop client connection
        self.stop()

    def banUser(self, paramReason: str | None):
        self.kickUser(paramReason)
        self.getServerBanList().append(self.getClientAddress()[0])

    """
            Packet Methods
    """

    def getPacketCollector(self) -> PacketCollector:
        """
        Returns the packet collector
        :return: Server / User packet collector
        """
        return self.__packetCollector

    def sendPacket(self, paramPacket: Packet) -> None:
        """
        Send a packet to the client
        :param paramPacket: The packet to send
        :return: None
        """
        if self.getReadyEvent().is_set():  # Check the client is ready to receive encrypted packets and
            # the server ready to send them
            sendPacket(paramPacket, (self.getConnection(), self.getClientPublicKey()))

    def sendToAllRecipients(self, paramPacket: Packet, ignore:
                            tuple[Any, types.FunctionType | type, Optional[tuple[Any]], Optional[dict[str, Any]]] |
                            list[tuple[Any, types.FunctionType | type, Optional[tuple[Any]], Optional[dict[str, Any]]]]
                            | None = None
                            ) -> None:
        """
        :param paramPacket: Packet to be sent
        :param ignore: Ignore where recipient ClientConnectionService.CLASS_METHOD(...) is equal to result
        :return: None
        """

        if ignore is None:
            # Send packet to all recipients since there is no ignoring
            # scs = ServerConnectionService
            sendPacket(paramPacket, [(scs.getConnection(), scs.getClientPublicKey())
                                     for scs in self.getServerUserList()])
            return

        # If some server connection services need to be ignore
        scs_list = self.getServerUserList()[:]  # Copy server user list

        if isinstance(ignore, tuple):
            ignore = [ignore]

        for ignoreExpression in ignore:
            result: Any = ignoreExpression[0]

            method_or_obj: types.FunctionType | type = ignoreExpression[1]

            args: tuple[Any] = ignoreExpression[2] if len(ignoreExpression) >= 3 and ignoreExpression[2]\
                is not None else ()
            kwargs: dict[str, Any] = ignoreExpression[3] if len(ignoreExpression) >= 4 and ignoreExpression[3] \
                is not None else {}

            # Choose connections to be used
            for serverConnectionService in scs_list[:]:  # Copy list again to stop concurrent modification

                if isinstance(method_or_obj, types.FunctionType):
                    if method_or_obj(serverConnectionService, *args, **kwargs) == result:
                        scs_list.remove(serverConnectionService)
                    continue

                if isinstance(method_or_obj, type):
                    if serverConnectionService == result:
                        scs_list.remove(serverConnectionService)
                    continue

        # Send the packet
        sendPacket(paramPacket, [(scs.getConnection(), scs.getClientPublicKey())
                                 for scs in scs_list])

    def getConnection(self) -> socket.socket:
        """
        Get the connection socket
        :return: Connection socket
        """
        return self.__connection

    def getClientAddress(self) -> tuple:
        """
        Get the client address
        :return: tuple(ip, port)
        """
        return self.__clientAddress

    def sendInfoToUser(self, paramMessage: str) -> None:
        """
        Send an info packet to the client
        :param paramMessage: The message to send
        :return: None
        """
        infoMessagePacket = InfoMessagePacket(paramMessage)  # Construct the info message packet
        self.sendPacket(infoMessagePacket)  # Send the packet

    def authenticate(self) -> None:
        """
        Authenticate the server with the client
        :return: None
        """
        try:

            """ 1) Validate Client Authentication """
            # 1.1) Await packet and unpack it
            authenticatePacket = self.getPacketCollector().awaitPacket(packet_type=PacketType.C2S_AUTHENTICATE)
            if self.getStopEvent().is_set():
                return
            if authenticatePacket is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_COLLECT_PACKET)

            authenticate_packetType, authenticate_packetBin = authenticatePacket  # Unpack the packet

            # 1.2) Authenticate channel hash
            if authenticate_packetBin.getAttribute("CHANNEL_HASH") != self.getChannelIDHash():
                raise ServerException(self.getStopEvent(), ServerException.INVALID_CHANNEL_ID_HASH)

            # 1.3) Load the public key
            der_key = authenticate_packetBin.getAttributeBytes("CLIENT_PUBLIC_KEY")

            client_public_key = serialization.load_der_public_key(
                der_key,
                backend=default_backend())

            # 1.4) Set the client public key
            self.setClientPublicKey(client_public_key)

            # 1.5) Encrypt the client challenge to the server
            clientEncryptedChallenge = self.getClientPublicKey().encrypt(
                # Concat the challenge with the the channel id in encrypted
                authenticate_packetBin.getAttributeBytes("CHALLENGE"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            """ 2) Send The Server Authenticate Packet To The Client """

            serverAuthenticatePacket = ServerAuthenticatePacket(self.getChannelID(),
                                                                self.getServerPublicKey(),
                                                                clientEncryptedChallenge)  # Construct the packet

            sendPacket(serverAuthenticatePacket, (self.getConnection(), None))  # Send the packet to client

            """ 3) Receive The Return Packet From The Client """
            # 3.1) Collect return packet
            authenticate_returnPacket = self.getPacketCollector() \
                .awaitPacket(packet_type=PacketType.C2S_AUTHENTICATE_RETURN)

            if self.getStopEvent().is_set():
                return

            # 3.2) Check if packet is valid
            if authenticate_returnPacket is None:
                raise ServerException(self.getStopEvent(), ServerException.MISSING_RETURN_PACKET)

            authenticate_return_packetType, authenticate_return_packetBin = authenticate_returnPacket  # Unpack packet

            # 3.3) Check the response hash
            if authenticate_return_packetBin.getAttribute("CHANNEL_HASH") != self.getChannelIDHash():
                raise ServerException(self.getStopEvent(), ServerException.INVALID_CHANNEL_ID_HASH)

            # 3.4) Check the decrypted challenge response
            decryptedClientChallenge = self.getServerPrivateKey().decrypt(
                authenticate_return_packetBin.getAttributeBytes("SIGNED_CHALLENGE"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 3.5) Check if client has successfully completed the challenge

            challenge_hmac: bytes = hmac.new(serverAuthenticatePacket.getChallenge(),
                                             self.getChannelID().encode('utf-8'),
                                             hashlib.sha256).digest()

            if decryptedClientChallenge != challenge_hmac:
                raise ServerException(self.getStopEvent(), ServerException.CLIENT_FAILED_CHALLENGE)

        except (ValueError, cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
            raise ServerException(self.getStopEvent(), ServerException.CRYPTOGRAPHY_EXCEPTION)

        except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
            raise ServerException(self.getStopEvent(), ServerException.SOCKET_EXCEPTION)

    def getUserData(self) -> None:
        """
        Gets and sets the user data
        :return: None
        """
        try:
            # 1) Send user data request
            serverRequestUserData = RequestUserData()  # Construct request user data packet
            self.sendPacket(serverRequestUserData)  # Send packet

            # 2) Receive user data from client
            user_dataPacket = self.getPacketCollector().awaitPacket(packet_type=PacketType.C2S_USER_DATA)
            if self.getStopEvent().is_set():
                return

            if user_dataPacket is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_USER_DATA)

            userData_packetType, userData_packetBin = user_dataPacket  # Unpack packet

            encodedDisplayName = userData_packetBin.getAttributeBytes("DISPLAY_NAME")  # Display name
            if encodedDisplayName is None or len(encodedDisplayName) == 0:  # Check the display name
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_USER_DATA)
            displayName = ''.join([char for char in encodedDisplayName.decode()
                                   if char in LEGAL_DISPLAY_NAME_CHARACTERS])  # Strip any illegal characters

            # 3) Set the user display name
            self.setDisplayName(displayName[:min(len(displayName), CHANNEL_USER_DISPLAY_NAME_MAX)])

            # 4) Check for server secret
            encodedServerSecret = userData_packetBin.getAttributeBytes("SERVER_SECRET")  # Server secret
            if encodedServerSecret is not None and len(encodedServerSecret) != 0:  # Check the server secret
                serverSecret = encodedServerSecret.decode('utf-8')
                if serverSecret == self.getServerSecret():
                    self.setAdminPermission(True)

            # 5) Check if the user receives files
            receiveFiles = userData_packetBin.getAttribute("RECEIVE_FILES")
            self.setReceivesFiles(bool(receiveFiles))


        except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
            raise ServerException(self.getStopEvent(), ServerException.SOCKET_EXCEPTION)

    def getClientServerErrors(self) -> list[str]:
        """
        Returns the list of reasons why client can't join the server
        :return: List of reasons why client can't join
        """
        userErrors = []  # Contains a list of all reasons why user can't join server

        if (len(self.getServerUserList()) + 1) > self.getMaxServerUsers():  # Check if server is full
            userErrors.append("Server is full!")

        if self.getConnection().getsockname()[0] in self.getServerBanList():  # Check if client is banned
            userErrors.append("You are banned from this channel!")

        for user in self.getServerUserList():
            if user.getDisplayName(False) == self.getDisplayName(False):
                userErrors.append("Someone with that display name is already online!")
                break

        if "admin" in self.getDisplayName(False).lower():
            userErrors.append("Admin is a protected name")

        if any([character not in string.ascii_letters + string.digits + "_" for character
                in self.getDisplayName(False)]):
            userErrors.append("Display name contains illegal characters")

        return userErrors  # Return all the errors

    def sendServerInformation(self) -> None:
        """
        Send the server information to client
        :return: None
        """

        message = [
            f"Currently Online: ({len(self.getServerUserList())}/{self.getMaxServerUsers()})",
            f"Users: {', '.join([user.getDisplayName(True) for user in self.getServerUserList()])}",
            f"Permission Level: {'Admin' if self.getAdminPermission() else 'User'}",
        ]

        infoMessagePacket = InfoMessagePacket("\n".join(message))
        self.sendPacket(infoMessagePacket)

    def startListener(self):
        """
        Listen and respond to socket
        :return:None
        """
        while not self.__stop.is_set():
            try:
                packet = self.getPacketCollector().awaitPacket()  # Await a packet from client
                if self.getStopEvent().is_set():
                    return

                if packet is None:  # If packet is none then it will fail to collect packet
                    raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_COLLECT_PACKET)

                packetType, packetBin = packet  # Unpack packet

                match packetType:
                    case PacketType.C2S_ALIVE_RESPONSE:
                        self.renewTime()

                    case PacketType.C2S_USER_LEAVE:
                        return  # Return as the user has left

                    case PacketType.C2S_TEXT_MESSAGE:
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")
                        if encodedMessage is None:
                            continue

                        message = encodedMessage.decode('utf-8')
                        if len(message) > MAXIMUM_MESSAGE_SIZE:
                            self.sendInfoToUser(f"Message exceeds maximum size of: {MAXIMUM_MESSAGE_SIZE}")
                            continue

                        textMessagePacket = TextMessagePacket(self.getDisplayName(True), message)
                        self.sendToAllRecipients(textMessagePacket)

                    case PacketType.C2S_FILE_SEND:

                        encodedFileName = packetBin.getAttributeBytes("FILE_NAME")
                        if encodedFileName is None:
                            continue

                        # Create confirmation packet
                        fileName = encodedFileName.decode('utf-8')
                        serverReceivedPacket = ServerReceivedFile(fileName)

                        file_bytes = packetBin.getAttributeBytes("FILE_DATA")

                        if "./" in fileName:
                            serverReceivedPacket.setError(f"File name contains './'")

                        # Add error to packet
                        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                            serverReceivedPacket.setError(f"File exceeds maximum size of: {MAX_FILE_SIZE_BYTES} bytes")

                        # Send confirmation to client that it received the file
                        self.sendPacket(serverReceivedPacket)

                        # continue if it has error
                        if serverReceivedPacket.getError() is not None:
                            continue

                        # Send file to everyone else who doesnt have receive files turned off
                        fileSendPacket = FileSendPacket(fileName, file_bytes, self.getDisplayName(True))
                        self.sendToAllRecipients(fileSendPacket,
                                                 ignore=[(False, ServerConnectionService.getReceiveFiles, None, None),
                                                         (self,  ServerConnectionService                , None, None)])

                    case _:
                        continue  # Received unrecognised packet

            except (cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
                raise ServerException(self.getStopEvent(), ServerException.CRYPTOGRAPHY_EXCEPTION)

            except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
                raise ServerException(self.getStopEvent(), ServerException.SOCKET_EXCEPTION)

    def run_safe(self):
        try:

            # 1) Authenticate and get public key
            self.authenticate()
            if self.getClientPublicKey() is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_CLIENT_PUBLIC_KEY)

            self.getReadyEvent().set()

            # 3) Get user info (just display name but expandable for later)
            self.getUserData()
            if self.getDisplayName(False) is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_CLIENT_CREDENTIALS)

            # 4) Check if user passes checks i.e bans, and number of people online
            if not self.getAdminPermission():
                clientServer_errors = self.getClientServerErrors()

                if len(clientServer_errors) > 0:
                    clientDisconnectPacket = ClientDisconnectPacket(", ".join(clientServer_errors))
                    self.sendPacket(clientDisconnectPacket)

                    raise ServerException(self.getStopEvent(), ServerException.CLIENT_REJECTED)

            # 5) Register user
            self.registerUser()

            self.sendServerInformation()

            self.startListener()

        finally:
            # 4) Close socket
            self.unregisterUser()
            self.getConnection().close()
