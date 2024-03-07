import logging

from Properties import MESSENGER_DEFAULT_LANGUAGE

logging.basicConfig(level=logging.INFO, format='%(message)s')
awaitingInput = False  # Awaiting input for concurrency

english = {
    "EMPTY_LINE": "",

    "FAIL_FILE_SAVED": "Failed to save file: %reason",
    "FILE_SAVED": "File has been saved to: %file_location",
    "SENDING_FILE": "Sending file: %file_name to %channel_id",
    "FILE_RECEIVED_CONFIRMATION": "Server received file: %file_name in %channel_id",
    "FILE_RECEIVED_CONFIRMATION_ERROR": "Server received file: %file_name in %channel_id, with error %error",
    "FILE_RECEIVED_CLIENT": "You received a file: %file_name in %channel_id, from %sender",

    "CHANNEL_CREATE": "Successfully created channel\n -> Terminal: %terminal\n -> Channel ID: %channel_id"
                      "\n -> Secret Key: %secret_key (Do not lose or share this!)\n -> IP: %ip"
                      "\n -> Port: %port\n -> Public: %public",
    "CHANNEL_CLOSE": "Stopped channel: %channel_id",

    "CHANNEL_USER_JOIN": "(%channel_id) [+] %display_name",
    "CHANNEL_USER_LEAVE": "(%channel_id) [-] %display_name",

    "CHANNEL_INFO": "(%channel_id) [INFO] %message",
    "CHANNEL_TEXT_MESSAGE": "(%channel_id) %display_name: >> %message",
    "CHANNEL_CLIENT_DISCONNECT": "(%channel_id) You have been disconnected",
    "CHANNEL_CLIENT_DISCONNECT_REASON": "(%channel_id) Disconnect reason: %reason",

    "MESSENGER_EXCEPTION": "Exception Occurred: %exception",
    "SERVICE_EXCEPTION": "Exception Occurred In Service %service: %exception",

    "MESSENGER_COMMAND": "%command: %arguments",
    "MESSENGER_START": "Starting Messenger Application",
    "MESSENGER_NO_CHANNEL": "Failed to find channel: %channel_id",
    "MESSENGER_JOIN_FAIL": "Failed to connect to channel: %channel_id | %channel_id",
    "MESSENGER_NO_ACTIVE_CHANNEL": "You must be connected to a channel to send a message",

    "MESSENGER_ACTIVE_CLIENT": "Set active client to: %channel_id",
    "MESSENGER_ACTIVE_SERVER": "Set active server to: %channel_id",

    "MESSENGER_INVALID_COMMAND": "You entered an invalid command: %command",
    "MESSENGER_USAGE": "Expected Usage: %usage",
}


class Language:
    def __init__(self, paramLanguage: str):
        """
        Language object
        :param paramLanguage:
        """
        match paramLanguage:
            case "english":  # Currently only have english language
                self.language = english
            case _:
                self.language = english

        self.__pseudo = {}  # Pseudo for language to replace

    def getPseudo(self) -> dict:
        """
        Get the pseudo values
        :return: dict of pseudo values
        """
        return self.__pseudo

    def get(self, paramLanguageAspect: str):
        """
        Returns the language aspect result
        :param paramLanguageAspect: language aspect (str)
        :return: text to be displayed (str)
        """
        return self.language.get(paramLanguageAspect,
                                 english.get(paramLanguageAspect, f"Invalid Language: {paramLanguageAspect}"))


language = Language(MESSENGER_DEFAULT_LANGUAGE)  # The default language


def awaitInput() -> str:
    """
    Await input from the messenger
    :return:
    """
    global awaitingInput
    print(f" > ", flush=True, end='')  # Display the initial prompt  # Ensure the prompt is displayed immediately

    awaitingInput = True
    user_input = input()  # Get user input
    awaitingInput = False

    print("\033[F\033[K", flush=True, end='')  # Move cursor up and clear the line
    return user_input


def addPseudo(paramArgument, paramReplaced, paramReplacement) -> None:
    """
    Add pseudo replacement
    :param paramArgument: Argument to be replaced
    :param paramReplaced: What should be replaced
    :param paramReplacement: Replacement text
    :return: None
    """
    if paramArgument in language.getPseudo():
        language.getPseudo()[paramArgument].add(paramReplaced, paramReplacement)
    else:
        language.getPseudo()[paramArgument] = {paramReplaced: paramReplacement}


def info(paramLanguageAspect, **arguments) -> None:
    """
    Output info to the messenger
    :param paramLanguageAspect: The language aspect to be output
    :param arguments: key word arguments for language aspect
    :return: None
    """

    # Find and replace all pseudo
    for key, value in arguments.items():
        if key in language.getPseudo():
            if value in language.getPseudo()[key]:
                arguments[key] = language.getPseudo()[key][value]

    # Get the message from the language aspect
    message = language.get(paramLanguageAspect)
    for key, value in arguments.items():
        message = message.replace(f"%{key}", value)

    # Output the message using logging class
    if awaitingInput:
        print("\"\033[2K\033[1G", flush=True, end='')  # Clear the line and move cursor back to the start
        logging.info(message)
        print(f" > ", flush=True, end=' ')  # Re display what was on the line

    else:
        logging.info(message)
