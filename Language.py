import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')

english = {
    "EXCEPTION": "Exception occurred: %s",
    "TERMINAL_FAIL": "Failed to connect to terminal: %s",

    "CHANNEL_CREATE": "Successfully created channel\n -> Terminal: %terminal\n -> Channel ID: %channel_id"
                      "\n -> Secret Key: %secret_key (Do not lose or share this!)\n -> IP: %ip"
                      "\n -> Port: %port\n -> Public: %public",
    "CHANNEL_CLOSE": "Stopped chanel: %channel_id",

    "CHANNEL_USER_JOIN": "(%channel_id) [+] %display_name",
    "CHANNEL_USER_LEAVE": "(%channel_id) [-] %display_name",

    "CHANNEL_INFO": "(%channel_id) [INFO] %message",
    "CHANNEL_TEXT_MESSAGE": "(%channel_id) %display_name: %message",

    "CHANNEL_CLIENT_DISCONNECT": "(%channel_id) You have been disconnected",
    "CHANNEL_CLIENT_DISCONNECT_REASON": "(%channel_id) Disconnect reason: %reason",
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

    logging.info(message)