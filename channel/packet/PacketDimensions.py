from utils.BinarySequencer import ArbitraryValue

"""
            Authentication Packets
            - Unencrypted
"""

C2S_AUTHENTICATE_DIMENSIONS = [("CHANNEL_HASH", 256),
                               ("PUBLIC_KEY_LENGTH", 16),
                               ("CLIENT_PUBLIC_KEY", ArbitraryValue.DYNAMIC),
                               ("CHALLENGE", 2048)]

S2C_AUTHENTICATE_DIMENSIONS = [("CHANNEL_HASH", 256),
                               ("PUBLIC_KEY_LENGTH", 16),
                               ("SERVER_PUBLIC_KEY", ArbitraryValue.DYNAMIC),
                               ("CHALLENGE", 2048),
                               ("SIGNED_CHALLENGE", 4096)]

C2S_AUTHENTICATE_RETURN_DIMENSIONS = [("CHANNEL_HASH", 256),
                                      ("SIGNED_CHALLENGE", 4096)]

"""
            Standard Packets
            - Encrypted
"""

"""
        Server -> Client
"""

S2C_USER_JOIN = [("DISPLAY_NAME_LENGTH", ArbitraryValue.DYNAMIC),
                 ("DISPLAY_NAME", ArbitraryValue.DYNAMIC)]

S2C_USER_LEAVE = [("DISPLAY_NAME_LENGTH", ArbitraryValue.DYNAMIC),
                  ("DISPLAY_NAME", ArbitraryValue.DYNAMIC)]

S2C_TEXT_MESSAGE = [("DISPLAY_NAME", ArbitraryValue.DYNAMIC),
                    ("MESSAGE", ArbitraryValue.DYNAMIC)]

S2C_INFO_MESSAGE = [("MESSAGE", ArbitraryValue.DYNAMIC)]

S2C_CLIENT_DISCONNECT = [("REASON", ArbitraryValue.DYNAMIC)]

S2C_REQUEST_USER_DATA = []

S2C_ALIVE = []

"""
        Client -> Server
"""

C2S_USER_DATA = [("DISPLAY_NAME_LENGTH", ArbitraryValue.DYNAMIC),
                 ("DISPLAY_NAME", ArbitraryValue.DYNAMIC)]

C2S_TEXT_MESSAGE = [("MESSAGE", ArbitraryValue.DYNAMIC)]

C2S_ALIVE_RESPONSE = []

C2S_USER_LEAVE = []
