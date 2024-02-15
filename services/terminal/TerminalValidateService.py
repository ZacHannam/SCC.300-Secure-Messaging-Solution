import requests

from services import Service
from Properties import TERMINAL_VERSION


class TerminalValidateService(Service.ServiceThread):
    def __init__(self, paramTerminalURL: str):
        super().__init__(Service.ServiceType.TERMINAL_VALIDATE)

        self.__terminalURL = paramTerminalURL
        self.__result = None

    def getTerminalURL(self) -> str:
        return self.__terminalURL

    def getResult(self) -> bool:
        return self.__result

    def __validateTerminal(self) -> bool:

        try:
            response = requests.get(self.getTerminalURL() + "/status")
        except requests.RequestException:
            return False

        # Check request has reached the terminal
        if response.status_code != 200:
            return False

        # Check if it is a json response
        if response.headers.get('Content-Type') != "application/json":
            return False

        try:
            responseJson = response.json()

            terminal, version = responseJson['version'].split(":")
            active = bool(responseJson['active'])

            return active and version == TERMINAL_VERSION and terminal == "TERMINAL"

        except (KeyError, ValueError, AttributeError):
            return False

    def run(self):
        self.__result = self.__validateTerminal()
