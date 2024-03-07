import os
import subprocess
import sys
from threading import Event
import hashlib
import socket

import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding

from Properties import MAX_FILE_SIZE_BYTES, FILE_SAVE_LOCATION, AUTOMATICALLY_OPEN_FILES
from channel.client.packet.C2S_FIleSendPacket import FileSendPacket
from utils.Language import info
from utils.MessengerExceptions import ClientException
from channel.Packet import PacketCollector, sendPacket, PacketType
from channel.client.packet.C2S_AliveReturnPacket import AliveReturnPacket
from channel.client.packet.C2S_AuthenticatePacket import ClientAuthenticatePacket
from channel.client.packet.C2S_ReturnAuthenticatePacket import ClientAuthenticateReturnPacket
from channel.client.packet.C2S_TextMessagePacket import TextMessagePacket
from channel.client.packet.C2S_UserDataPacket import UserDataPacket
from channel.client.packet.C2S_UserLeavePacket import UserLeavePacket
from channel import Service


class ClientConnectionService(Service.ServiceThread):
    def __init__(self, paramServerIP: str, paramServerPort: int, paramStopEvent: Event,
                 paramClientDisplayName: str, paramChannelID: str,
                 paramClientPrivateKey: RSAPrivateKey, paramServerPublicKey: RSAPublicKey,
                 paramServerSecret: str | None):
        super().__init__(Service.ServiceType.CLIENT_CONNECTION)  # Establish the service thread

        self.__serverIP: str = paramServerIP
        self.__serverPort: int = paramServerPort
        self.__clientDisplayName: str = paramClientDisplayName
        self.__channelID: str = paramChannelID
        self.__clientPrivateKey: RSAPrivateKey = paramClientPrivateKey
        self.__serverPublicKey: RSAPublicKey = paramServerPublicKey
        self.__serverSecret: str | None = paramServerSecret


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

    def getServerSecret(self) -> str | None:
        """
        Return the server secret if it is set
        :return:
        """
        return self.__serverSecret

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

    def sendFileBytes(self, paramFileName, paramFileBytes):
        """
        Send file bytes to server
        :param paramFileName: Name of file
        :param paramFileBytes: File bytes
        :return:
        """
        fileSendPacket = FileSendPacket(paramFileName, paramFileBytes)
        self.sendPacket(fileSendPacket)


    def sendUserDataPacket(self) -> None:
        """
        Send the clients user data to the server
        :return: None
        """
        # Construct the user data packet
        userDataPacket = UserDataPacket(self.getClientDisplayName(), self.getServerSecret())
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
            der_key = authenticate_packetBin.getAttributeBytes("SERVER_PUBLIC_KEY")

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

                        message = encodedMessage.decode('utf-8')  # Decode the message
                        message_lines = message.split("\n")
                        for line in message_lines:
                            info("CHANNEL_INFO", channel_id=self.getChannelID(),  # Send the info message
                                 message=line)

                    case PacketType.S2C_TEXT_MESSAGE:  # Wait for a text message
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")  # Get the message
                        encodedDisplayName = packetBin.getAttributeBytes("DISPLAY_NAME")  # Get the display name
                        if encodedMessage is None or len(encodedMessage) == 0:  # Check the message is not empty
                            continue

                        if encodedDisplayName is None or len(encodedDisplayName) == 0:  # Check the display name
                            continue

                        message = encodedMessage.decode('utf-8')  # Decode the message
                        displayName = encodedDisplayName.decode('utf-8')  # Decode the display name

                        info("CHANNEL_TEXT_MESSAGE", channel_id=self.getChannelID(),  # Output the message
                             display_name=displayName, message=message)

                    case PacketType.S2C_SERVER_RECEIVED_FILE:  # Wait to see if a file confirmation is received

                        encodedFileName = packetBin.getAttributeBytes("FILE_NAME")  # Get the file name name
                        if encodedFileName is None or len(encodedFileName) == 0:  # Check the file name is not empty
                            continue

                        file_name = encodedFileName.decode('utf-8')

                        encodedError = packetBin.getAttributeBytes("ERROR")  # Get the file name name
                        if encodedError is None or len(encodedError) == 0:  # Check the file name is not empty
                            info("FILE_RECEIVED_CONFIRMATION", channel_id=self.getChannelID(),  # Output the message
                                 file_name=file_name)
                        else:
                            error = encodedError.decode('utf-8')
                            info("FILE_RECEIVED_CONFIRMATION_ERROR", channel_id=self.getChannelID(),  # with error
                                 file_name=file_name, error=error)

                    case PacketType.S2C_FILE_SEND:

                        encodedFileName = packetBin.getAttributeBytes("FILE_NAME")  # Get the file name name
                        if encodedFileName is None or len(encodedFileName) == 0:  # Check the file name is not empty
                            continue

                        encodedSender = packetBin.getAttributeBytes("FILE_SENDER")  # Get the file name name
                        if encodedSender is None or len(encodedSender) == 0:  # Check the file name is not empty
                            continue

                        file_bytes = packetBin.getAttributeBytes("FILE_DATA")
                        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                            continue  # Continue as file is too large

                        file_name = encodedFileName.decode('utf-8')
                        file_sender = encodedSender.decode('utf-8')

                        info("FILE_RECEIVED_CLIENT", file_name=file_name, channel_id=self.getChannelID(),
                             sender=file_sender)

                        saveFile(file_name, file_bytes)

                    case _:
                        continue  # Received unrecognised packet

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


def openFileWithDefaultApp(paramFilePath: str) -> None:
    """
    Open the file using the default application associated with its file type.
    :param: open the file path
    :return: None
    """
    if sys.platform.startswith('win'):
        os.startfile(paramFilePath)
    elif sys.platform.startswith('darwin'):
        subprocess.call(['open', paramFilePath])
    else:
        subprocess.call(['xdg-open', paramFilePath])


def getAppDataDirectory() -> str:
    """
    Get the application data directory for the specified application name.
    :return: Get the app data directory
    """
    if sys.platform.startswith('win'):
        # Windows
        app_data_dir = os.path.join(os.getenv('APPDATA'), )
    elif sys.platform.startswith('darwin'):
        # macOS
        app_data_dir = os.path.expanduser(f'~/Library/Application Support/{FILE_SAVE_LOCATION}')
    else:
        # Linux (and other Unix-like systems)
        app_data_dir = os.path.expanduser(f'~/.{FILE_SAVE_LOCATION}')

    return app_data_dir


def saveFile(paramFileName: str, paramFileBytes: bytes) -> None:
    """
    Used to save incoming files from the connection
    :param paramFileName: File name
    :param paramFileBytes: File bytes
    :return: None
    """

    appDataDirectory = getAppDataDirectory()

    # Check if the directory exists, if not, create it
    if not os.path.exists(appDataDirectory):
        os.makedirs(appDataDirectory)

    # Save the file in the application data directory
    file_path: str = os.path.join(appDataDirectory, paramFileName)

    try:
        with open(file_path, 'wb') as file:
            file.write(paramFileBytes)

        info("FILE_SAVED", file_location=file_path)

        if AUTOMATICALLY_OPEN_FILES:
            openFileWithDefaultApp(file_path)

    except Exception as exception:
        info("FAIL_FILE_SAVED", reason=str(exception))