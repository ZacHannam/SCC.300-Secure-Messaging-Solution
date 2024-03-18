import string
from enum import Enum

CHANNEL_BIN_INVALIDATE_DIMENSIONS = [(   "CHANNEL_SECRET_BIN" ,  256     ),
                                     (   "UNIQUE_AUTH_HI"     ,  32      ),
                                     (   "UNIQUE_AUTH_LO"     ,  32      )]

CHANNEL_BIN_DIMENSIONS        = [(   "CHANNEL_SECRET_BIN" ,  256     ),
                                 (   "CHANNEL_INFO_BIN"   ,  512     )]

CHANNEL_INFO_BIN_DIMENSIONS   = [(   "UNIQUE_AUTH_HI"     ,  32      ),
                                 (   "UNIQUE_AUTH_LO"     ,  32      ),
                                 (   "IP_TYPE"            ,  2       ),
                                 (   "IP_PLACEMENT"       ,  9       ),
                                 (   "IP"                 ,  421     ),
                                 (   "PORT"               ,  16      )]


"""

                GENERAL SETTINGS

"""


class IPType(Enum):
    """
    IP Type Enum
    """
    IPv4   = 0
    IPv6   = 1
    Tunnel = 2


"""
        Client and Server
"""

RSA_KEY_SIZE                   = 4096                                   # Key size for RSA
DEFAULT_PORT_SERVER            = 28961                                  # Default server port
CHANNEL_USER_DISPLAY_NAME_MAX  = 16                                     # Number of characters in display name
CHANNEL_ID_LENGTH              = (14, 20)                               # Channel ID length (generated)
CHANNEL_SECRET_KEY_LENGTH      = (20, 28)                               # Channel Secret Key (generated)
NAMES_LIST_FILE                = "utils/names_list.txt"                 # List of names for generated names
EULA_FILE                      = "eula.txt"                             # EULA file for hosting server
PACKET_MAX_SIZE                = 8192                                   # Packet size maximum (bits)
ALIVE_TIME                     = 20                                     # Seconds between sending alive packets
ALIVE_TIMEOUT                  = 120                                    # Alive timeout
MAXIMUM_MESSAGE_SIZE           = 500                                    # Character limit for messages
COMMAND_KEY                    = '/'                                    # Messenger command character
DEFAULT_BAN_REASON             = "You were banned from this channel!"   # Default ban reason
LEGAL_DISPLAY_NAME_CHARACTERS  = string.ascii_letters + string.digits   # List of allowed username characters
MESSENGER_DEFAULT_LANGUAGE     = "english"                              # Default language for messenger
MAX_FILE_SIZE_BYTES            = 1_000_000_000                          # Maximum file size
FILE_SAVE_LOCATION             = "Messenger/saved-files"                # Where files should be saved on the client
RECEIVE_FILES                  = True                                   # If the client is receiving files
AUTOMATICALLY_OPEN_FILES       = False                                  # Automatically opened saved files
SEND_HIDDEN_FILES              = False                                  # Send hidden files (start with .)

"""
        Terminal
"""

TERMINAL_VERSION               = "VERSION-1"                            # Terminal and Client version
TERMINAL_PROTOCOL              = ["http://", "https://"]                # Protocols that the terminal could use
