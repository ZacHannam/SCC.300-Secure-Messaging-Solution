from enum import Enum

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


CHANNEL_USER_DISPLAY_NAME_MAX  = 16                                     # Number of characters in display name
CHANNEL_ID_LENGTH              = (14, 20)                               # Channel ID length (generated)
CHANNEL_SECRET_KEY_LENGTH      = (20, 28)                               # Channel Secret Key (generated)
DEFAULT_PORT_SERVER            = 28961                                  # Default server port
NAMES_LIST_FILE                = "names_list.txt"                       # List of names for generated names
TERMINAL_VERSION               = "beta0.1"                              # Terminal and Client version
PACKET_MAX_SIZE                = 8192                                   # Packet size maximum (bits)
ALIVE_TIME                     = 1                                      # Seconds between sending alive packets
MAXIMUM_MESSAGE_SIZE           = 500                                    # Character limit for messages
COMMAND_KEY                    = '/'                                    # Messenger command character
TERMINAL_PROTOCOL              = ["http://", "https://"]                # Protocols that the terminal could use
DEFAULT_BAN_REASON             = "You were banned from this channel!"   # Default ban reason