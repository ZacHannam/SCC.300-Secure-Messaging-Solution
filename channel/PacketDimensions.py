from utils.BinarySequencer import ArbitraryValue

"""
            Authentication Packets
            - Unencrypted
"""

C2S_AUTHENTICATE_DIMENSIONS = [("CHANNEL_HASH", 256),
                               ("CLIENT_PUBLIC_KEY", ArbitraryValue.DYNAMIC),
                               ("CHALLENGE", ArbitraryValue.DYNAMIC)]

S2C_AUTHENTICATE_DIMENSIONS = [("CHANNEL_HASH", 256),
                               ("SERVER_PUBLIC_KEY", ArbitraryValue.DYNAMIC),
                               ("CHALLENGE", ArbitraryValue.DYNAMIC),
                               ("SIGNED_CHALLENGE", ArbitraryValue.DYNAMIC)]

C2S_AUTHENTICATE_RETURN_DIMENSIONS = [("CHANNEL_HASH", 256),
                                      ("SIGNED_CHALLENGE", ArbitraryValue.DYNAMIC)]

"""
            Standard Packets
            - Encrypted
"""

"""
        Server -> Client
"""

S2C_USER_JOIN = [("DISPLAY_NAME", ArbitraryValue.DYNAMIC)]

S2C_USER_LEAVE = [("DISPLAY_NAME", ArbitraryValue.DYNAMIC)]

S2C_TEXT_MESSAGE = [("DISPLAY_NAME", ArbitraryValue.DYNAMIC),
                    ("MESSAGE", ArbitraryValue.DYNAMIC)]

S2C_INFO_MESSAGE = [("MESSAGE", ArbitraryValue.DYNAMIC)]

S2C_CLIENT_DISCONNECT = [("REASON", ArbitraryValue.DYNAMIC)]

S2C_REQUEST_USER_DATA = []

S2C_ALIVE = []

S2C_FILE_SEND = [("FILE_NAME", ArbitraryValue.DYNAMIC),
                 ("FILE_DATA", ArbitraryValue.DYNAMIC),
                 ("FILE_SENDER", ArbitraryValue.DYNAMIC)]

S2C_SERVER_RECEIVED_FILE = [("FILE_NAME", ArbitraryValue.DYNAMIC),
                            ("ERROR", ArbitraryValue.DYNAMIC)]

"""
        Client -> Server
"""

C2S_USER_DATA = [("DISPLAY_NAME", ArbitraryValue.DYNAMIC),
                 ("RECEIVE_FILES", 1),
                 ("SERVER_SECRET", ArbitraryValue.DYNAMIC)]

C2S_TEXT_MESSAGE = [("MESSAGE", ArbitraryValue.DYNAMIC)]

C2S_ALIVE_RESPONSE = []

C2S_USER_LEAVE = []

C2S_FILE_SEND = [("FILE_NAME", ArbitraryValue.DYNAMIC),
                 ("FILE_DATA", ArbitraryValue.DYNAMIC)]
