import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')

english = {
    "EMPTY_LINE": "",

    "CHANNEL_CREATE": "Successfully created channel\n -> Terminal: %terminal\n -> Channel ID: %channel_id"
                      "\n -> Secret Key: %secret_key (Do not lose or share this!)\n -> IP: %ip"
                      "\n -> Port: %port\n -> Public: %public",
    "CHANNEL_CLOSE": "Stopped channel: %channel_id",

    "CHANNEL_USER_JOIN": "(%channel_id) [+] %display_name",
    "CHANNEL_USER_LEAVE": "(%channel_id) [-] %display_name",

    "CHANNEL_INFO": "(%channel_id) [INFO] %message",
    "CHANNEL_TEXT_MESSAGE": "(%channel_id) %display_name: %message",
    "CHANNEL_CLIENT_DISCONNECT": "(%channel_id) You have been disconnected",
    "CHANNEL_CLIENT_DISCONNECT_REASON": "(%channel_id) Disconnect reason: %reason",

    "MESSENGER_EXCEPTION": "Exception Occurred: %exception",
    "SERVICE_EXCEPTION": "Exception Occurred In Service: %exception",

    "MESSENGER_COMMAND": "%command: %arguments",
    "MESSENGER_START": "Starting Messenger Application",
    "MESSENGER_NO_CHANNEL": "Failed to find channel: %channel_id",
    "MESSENGER_JOIN_FAIL": "Failed to connect to channel: %channel_id | %channel_id",
    "MESSENGER_NO_ACTIVE_CHANNEL": "You must be connected to a channel to send a message",

    "MESSENGER_ACTIVE_CLIENT": "Set active client to: %channel_id",
    "MESSENGER_ACTIVE_SERVER": "Set active server to: %channel_id",

    "INVALID_COMMAND": "You entered an invalid command: %command",
    "MESSENGER_USAGE": "Expected Usage: %usage",
}


class Language:
    def __init__(self, paramLanguage: str):
        match paramLanguage:
            case "english":
                self.language = english
            case _:
                self.language = english

        self.__pseudo = {}

    def getPseudo(self) -> dict:
        return self.__pseudo

    def get(self, paramLanguageAspect):
        return self.language.get(paramLanguageAspect,
                                 english.get(paramLanguageAspect, f"Invalid Language: {paramLanguageAspect}"))


language = Language("english")

awaitingInput = False


def awaitInput() -> str:
    global awaitingInput
    print(f" > ", flush=True, end='')  # Display the initial prompt  # Ensure the prompt is displayed immediately

    awaitingInput = True
    user_input = input()  # Get user input
    awaitingInput = False

    print("\033[F\033[K", flush=True, end='')  # Move cursor up and clear the line
    return user_input


def addPseudo(paramArgument, paramReplaced, paramReplacement):
    if paramArgument in language.getPseudo():
        language.getPseudo()[paramArgument].add(paramReplaced, paramReplacement)
    else:
        language.getPseudo()[paramArgument] = {paramReplaced: paramReplacement}


def info(paramLanguageAspect, **arguments):

    for key, value in arguments.items():
        if key in language.getPseudo():
            if value in language.getPseudo()[key]:
                arguments[key] = language.getPseudo()[key][value]

    message = language.get(paramLanguageAspect)
    for key, value in arguments.items():
        message = message.replace(f"%{key}", value)

    if awaitingInput:
        print("\"\033[2K\033[1G", flush=True, end='')  # Clear the line and move cursor back to the start
        logging.info(message)
        print(f" > ", flush=True, end=' ')  # Re display what was on the line

    else:
        logging.info(message)
