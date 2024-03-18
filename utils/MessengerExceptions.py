from threading import Event


class MessengerException(Exception):
    class Exception:
        def __init__(self, paramFatal: bool, paramMessage: str):
            """
            Exception class for client exception
            :param paramFatal:
            :param paramMessage:
            """
            self.fatal = paramFatal
            self.message = paramMessage

        def isFatal(self) -> bool:
            """
            Returns if the exception is fatal
            :return: Exception is fatal (bool)
            """
            return self.fatal

        def getMessage(self) -> str:
            """
            Returns the message for the exception
            :return: The exception message (str)
            """
            return self.message

    def __init__(self, paramStopSignal: Event | None, paramException: Exception):
        """
        Client Exception thrown in the client
        :param paramStopSignal: The stop signal for the client
        :param paramException: The exception being used
        """
        super().__init__()
        self.message = paramException.getMessage()  # Set the exception message

        if paramException.isFatal() and paramStopSignal is not None:  # Stop the client threads if it is fatal
            paramStopSignal.set()


class ServerException(MessengerException):
    """
            Exceptions
    """

    SOCKET_EXCEPTION = MessengerException.Exception(True, "Socket failure")
    INVALID_TERMINAL_URL = MessengerException.Exception(True, "Invalid Terminal URL")
    FAILED_TO_COLLECT_PACKET = MessengerException.Exception(True, "Failed to collect packet")
    INVALID_CHANNEL_ID_HASH = MessengerException.Exception(True, "Invalid channel ID hash in packet")
    CLIENT_FAILED_CHALLENGE = MessengerException.Exception(True, "Client failed authenticate challenge")
    MISSING_RETURN_PACKET = MessengerException.Exception(True, "Failed to authenticate, client didn't send response "
                                                               "packet")
    CRYPTOGRAPHY_EXCEPTION = MessengerException.Exception(True, "Cryptography failed")
    FAILED_TO_AUTHENTICATE = MessengerException.Exception(True, "Server failed to authenticate")
    FAILED_TO_GET_USER_DATA = MessengerException.Exception(True, "Failed to get user data")
    FAILED_TO_GET_CLIENT_PUBLIC_KEY = MessengerException.Exception(True, "Failed to get client public key")
    FAILED_TO_GET_CLIENT_CREDENTIALS = MessengerException.Exception(True, "Failed to get client credentials")
    CLIENT_REJECTED = MessengerException.Exception(True, "Client was rejected from joining server")
    FAILED_TO_GET_IP = MessengerException.Exception(True, "Failed to get external IP")
    FAILED_TO_UNVALIDATE_TERMINAL = MessengerException.Exception(True, "Failed to unvalidate terminal")
    FAILED_TO_VALIDATE_TERMINAL = MessengerException.Exception(True, "Failed to validate terminal")
    FAILED_TO_PUBLISH_CHANNEL = MessengerException.Exception(True, "Failed to publish channel")
    FAILED_TO_UNPUBLISH_CHANNEL = MessengerException.Exception(True, "Failed to unpublish channel")
    SERVER_ALREADY_ON_PORT = MessengerException.Exception(True,
                                                          "Failed to bind channel to port (Server already running "
                                                          "on port)")
    INVALID_IP_FORMAT = MessengerException.Exception(False, "Failed to correctly format IP")
    FAILED_TO_FIND_USER = MessengerException.Exception(False, "Failed to find user by their display name")
    FAILED_TO_START_HOST_SERVICE = MessengerException.Exception(True, "Failed to start host service")

    EULA_FALSE = MessengerException.Exception(False, "Please read and agree to the EULA within the provided EULA file")
    ERROR_OPENING_EULA = MessengerException.Exception(False, "Failed to open EULA file")
    EULA_DOES_NOT_EXIST = MessengerException.Exception(True, "Failed to find EULA file")
    NO_EULA_VARIABLE = MessengerException.Exception(True, "No EULA Variable in EULA file")


class ClientException(MessengerException):
    """
            Exceptions
    """

    INVALID_TERMINAL_URL = MessengerException.Exception(True, "Invalid Terminal URL")
    FAILED_TO_COLLECT_PACKET = MessengerException.Exception(True, "Failed to collect packet")
    INVALID_CHANNEL_ID_HASH = MessengerException.Exception(True, "Invalid channel ID hash in packet")
    SERVER_FAILED_CHALLENGE = MessengerException.Exception(True, "Server failed authenticate challenge")
    FAILED_TO_DECODE_PACKET = MessengerException.Exception(False, "Failed to decode packet")
    FAILED_TO_GET_SERVER_PUBLIC_KEY = MessengerException.Exception(True, "Failed to get server public key")
    SOCKET_EXCEPTION = MessengerException.Exception(True, "Socket failure")
    FAILED_TO_CREATE_CLIENT_FROM_BIN = MessengerException.Exception(False, "Failed to create client from binary"
                                                                           " sequencer")
    INVALID_IP_TYPE = MessengerException.Exception(False, "Invalid IP type encountered")
    NO_CHANNEL_ON_TERMINAL = MessengerException.Exception(False, "Failed to find channel on terminal")
    FAILED_TO_AUTHENTICATE = MessengerException.Exception(True, "Client failed to authenticate")
    CRYPTOGRAPHY_EXCEPTION = MessengerException.Exception(True, "Cryptography failed")
    FAILED_TO_CONNECT_TIMEOUT = MessengerException.Exception(True, "Failed to connect to server (Timed out)")
    FAILED_TO_LEAVE_SERVER = MessengerException.Exception(True, "Failed to leave server")
    FAILED_VALIDATE_TERMINAL = MessengerException.Exception(True, "Failed to validate terminal")

    FAILED_TO_FIND_FILE = MessengerException.Exception(False, "Failed to find file or directory")
    EXCEEDS_MAX_FILE_SIZE = MessengerException.Exception(False, "File exceeds max file size")



class PacketException(MessengerException):
    """
            Exceptions
    """

    CONTENT_TOO_LARGE = MessengerException.Exception(False, "Packet content is too large")
    PACKET_INCORRECT_DIMENSIONS = MessengerException.Exception(False, "Unexpected packet dimensions for packet type")
    PACKET_EXPECTED_ENCRYPTION = MessengerException.Exception(False, "Expected encryption for packet and got none")
    FAILED_TO_SEND_PACKET = MessengerException.Exception(False, "Failed to send packet (Broken Pipe)")
    PACKET_COLLECT_SOCKET_CLOSED = MessengerException.Exception(True, "Packet collector socket closed")
    PACKET_INCORRECT_SIZE = MessengerException.Exception(False, "Failed to decode packet due to its length")
    UNEXPECTED_PACKET_TYPE = MessengerException.Exception(False, "Packet collector received unrecognised packet type")
    PACKET_IDENTITY_INCORRECT = MessengerException.Exception(False, "A packet was wrongfully given sequence number")


class Base85Exception(MessengerException):
    """
            Exceptions
    """
    INVALID_NUMBER_OF_CHARACTERS_ENCODE = MessengerException.Exception(False, "Number of characters must be a "
                                                                              "multiple of 5")
    INVALID_NUMBER_OF_CHARACTERS_DECODE = MessengerException.Exception(False, "Number of characters must be a "
                                                                              "multiple of 4")
    INVALID_CHARACTER = MessengerException.Exception(False, "Character is not in the base85 alphabet")


class BinarySequencerException(MessengerException):
    """
            Exceptions
    """
    INVALID_DIMENSIONS = MessengerException.Exception(False, "Dimensions do not fit [(a, b, ?), ...]")
    INVALID_POPULATION_TYPE = MessengerException.Exception(False, "Population must be an integer or bytes")
    CANNOT_XOR_DYNAMIC_BIN = MessengerException.Exception(False, "Cannot use xor when there is a dynamic bin")
    CANNOT_RANDOMISE_DYNAMIC_BIN = MessengerException.Exception(False, "Cannot apply a randomised value to a dynamic "
                                                                       "bin")
    ATTRIBUTE_TOO_LARGE = MessengerException.Exception(False, "Attribute value does not fit in container")
