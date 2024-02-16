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

CHANNEL_USER_DISPLAY_NAME_MAX  = 16                                 # Number of characters in display name
CHANNEL_ID_LENGTH              = (14, 20)                           # Channel ID length (generated)
CHANNEL_SECRET_KEY_LENGTH      = (20, 28)                           # Channel Secret Key (generated)
DEFAULT_PORT_SERVER            = 28961                              # Default server port
DEFAULT_PORT_CLIENT            = 28962                              # Default port of client
NAMES_LIST_FILE                = "names_list.txt"                   # List of names for generated names
TERMINAL_VERSION               = "beta0.1"                          # Terminal and Client version
PACKET_MAX_SIZE                = 8192                               # Packet size maximum (bits)
ALIVE_TIME                     = 10                                 # Seconds between sending alive packets
MAXIMUM_MESSAGE_SIZE           = 500                                # Character limit for messages