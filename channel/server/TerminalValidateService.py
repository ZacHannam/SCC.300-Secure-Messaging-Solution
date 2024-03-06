import requests

from Properties import TERMINAL_VERSION
from channel import Service


class TerminalValidateService(Service.ServiceThread):
    def __init__(self, paramTerminalURL: str):
        """
        Validate the terminal
        :param paramTerminalURL:
        """
        super().__init__(Service.ServiceType.TERMINAL_VALIDATE)

        self.__terminalURL: str = paramTerminalURL
        self.__result: None | bool = None

    def getTerminalURL(self) -> str:
        """
        Get the terminal URL
        :return: terminal url (str)
        """
        return self.__terminalURL

    def getResult(self) -> bool:
        """
        Get the result value
        :return: result bool
        """
        return self.__result

    def validateTerminal(self) -> None:
        """
        Validate the terminal
        :return: None
        """
        try:
            response = requests.get(self.getTerminalURL() + "/status")
        except requests.RequestException:
            self.__result = False
            return

        # Check request has reached the terminal
        if response.status_code != 200:
            self.__result = False
            return

        # Check if it is a json response
        if response.headers.get('Content-Type') != "application/json":
            self.__result = False
            return

        try:
            responseJson = response.json()

            terminal, version = responseJson['version'].split(":")
            active = bool(responseJson['active'])

            self.__result = active and version == TERMINAL_VERSION and terminal == "TERMINAL"

        except (KeyError, ValueError, AttributeError):
            self.__result = False

    def run_safe(self):
        self.validateTerminal()
