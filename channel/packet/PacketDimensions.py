from utils.BinarySequencer import ArbitraryValue

"""
            PACKETS ACCEPTING SIZE OF 16384 (16376 USABLE) 2kB
            - Unencrypted
"""

C2S_CHALLENGE_DIMENSIONS = [( "CHANNEL_HASH"      , 256                    ),
                            ( "PUBLIC_KEY_LENGTH" , 16                     ),
                            ( "CLIENT_PUBLIC_KEY" , ArbitraryValue.DYNAMIC ),
                            ( "CHALLENGE"         , 2048                   )]

S2C_CHALLENGE_DIMENSIONS = [( "CHANNEL_HASH"      , 256                    ),
                            ( "PUBLIC_KEY_LENGTH" , 16                     ),
                            ( "SERVER_PUBLIC_KEY" , ArbitraryValue.DYNAMIC ),
                            ( "CHALLENGE"         , 2048                   ),
                            ( "SIGNED_CHALLENGE"  , 4096                   )]

C2S_CHALLENGE_RETURN_DIMENSIONS = [( "CHANNEL_HASH"      , 256  ),
                                   ( "SIGNED_CHALLENGE"  , 4096 )]

"""
            PACKETS ACCEPTING SIZE OF 512 (504 USABLE) 0.5kB
            - Encrypted
"""

S2C_REQUEST_USER_DATA = []

C2S_USER_DATA = [( "DISPLAY_NAME_LENGTH" , ArbitraryValue.DYNAMIC ),
                 ( "DISPLAY_NAME"        , ArbitraryValue.DYNAMIC )]

S2C_USER_JOIN = [( "DISPLAY_NAME_LENGTH" , ArbitraryValue.DYNAMIC ),
                 ( "DISPLAY_NAME"        , ArbitraryValue.DYNAMIC )]

S2C_USER_LEAVE = [( "DISPLAY_NAME_LENGTH" , ArbitraryValue.DYNAMIC),
                  ( "DISPLAY_NAME"        , ArbitraryValue.DYNAMIC )]

S2C_ALIVE = []

C2S_ALIVE_RESPONSE = []

C2S_TEXT_MESSAGE  = [("MESSAGE", ArbitraryValue.DYNAMIC)]

S2C_TEXT_MESSAGE = [( "DISPLAY_NAME"         , ArbitraryValue.DYNAMIC ),
                    ( "MESSAGE"             , ArbitraryValue.DYNAMIC  )]

S2C_INFO_MESSAGE  = [("MESSAGE", ArbitraryValue.DYNAMIC)]