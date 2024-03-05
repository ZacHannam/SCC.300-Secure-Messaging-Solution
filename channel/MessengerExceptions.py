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
    CLIENT_FAILED_CHALLENGE = MessengerException.Exception(True, "Server failed authenticate challenge")
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
