import re
from typing import Any
import sys

from Properties import COMMAND_KEY
from utils.Language import info, awaitInput
from channel.client.Client import Client, getClientFromTerminalScan
from channel.server.Server import Server
from utils.MessengerExceptions import MessengerException


class Messenger:
    def __init__(self):
        """
        Main Messenger Application
        """
        self.__activeClient: Client | None   = None
        self.__activeServer: Server | None   = None
        self.__clients: list[Client]         = []
        self.__servers: list[Server]         = []

        self.printStartMessage()  # Print the start message
        self.mainloop()           # Start the main loop

    """
            Getter and Setter Methods
    """

    """
            Active Client and Server
    """

    def getActiveClient(self) -> Client | None:
        """
        Returns the active client that works else None
        :return: active client or None
        """
        # Check if the active client is None
        if self.__activeClient is None:
            return None

        # Make sure the active client is still alive
        if self.__activeClient.getStopEvent().is_set():
            self.removeClient(self.__activeClient)

        return self.__activeClient

    def setActiveClient(self, paramClient: Client) -> None:
        """
        Sets the active client
        :param: Client to make active
        :return: None
        """
        self.__activeClient = paramClient
        if self.__activeClient is not None:

            if self.__activeClient.getStopEvent().is_set():
                # Will not allow it to be set and recursively find one that isn't stopped until None
                self.removeClient(self.__activeClient)
                return

            info("MESSENGER_ACTIVE_CLIENT", channel_id=paramClient.getChannelID())
        else:
            info("MESSENGER_ACTIVE_CLIENT", channel_id="None")

    def getActiveServer(self) -> Server | None:
        """
        Returns the active server that works else None
        :return: active server or None
        """
        # Check if the active client is None
        if self.__activeServer is None:
            return None

        # Make sure the active client is still alive
        if self.__activeServer.getStopEvent().is_set():
            self.removeServer(self.__activeServer)

        return self.__activeServer

    def setActiveServer(self, paramServer: Server) -> None:
        """
        Sets the active server
        :param: Server to make active
        :return: None
        """

        self.__activeServer = paramServer
        if self.__activeServer is not None:

            if self.__activeServer.getStopEvent().is_set():
                # Will not allow it to be set and recursively find one that isn't stopped until None
                self.removeServer(self.__activeServer)
                return

            info("MESSENGER_ACTIVE_SERVER", channel_id=paramServer.getChannelID())
        else:
            info("MESSENGER_ACTIVE_SERVER", channel_id="None")


    """
            Clients and Servers
    """

    def getClients(self) -> list[Client]:
        """
        Returns a list of clients
        :return: Clients list
        """
        return self.__clients

    def addClient(self, paramClient: Client) -> None:
        """
        Add a client and set it to active client
        :param paramClient:
        :return:
        """
        self.__clients.append(paramClient)
        self.setActiveClient(paramClient)

    def removeClient(self, paramClient: Client) -> None:
        """
        Remove a client
        :param paramClient: Client to be removed
        :return: None
        """
        # Stop the client if its not already stopped
        if not paramClient.getStopEvent().is_set():
            paramClient.leaveServer()  # Leave the server
            paramClient.getStopEvent().set()  # Set the flag (Should be done when leaving the server)

        # Remove client from the list
        self.__clients.remove(paramClient)

        # Check if active client is the client to be removed, if so replace it
        if self.__activeClient == paramClient:
            self.setActiveClient(self.__clients[0] if len(self.__clients) else None)



    def getServers(self) -> list[Server]:
        """
        Returns a list of servers
        :return: Servers list
        """
        return self.__servers

    def addServer(self, paramServer: Server) -> None:
        """
        Add a server and set it to active server
        :param paramServer:
        :return:
        """
        self.__servers.append(paramServer)
        self.setActiveServer(paramServer)

    def removeServer(self, paramServer: Server) -> None:
        """
        Remove a server
        :param paramServer: Server to be removed
        :return: None
        """
        # Stop the server if its not already stopped
        if not paramServer.getStopEvent().is_set():
            paramServer.stopServer()  # Stop the server
            paramServer.getStopEvent().set()  # Set the flag (Should be done when leaving the server)

        # Remove server from the list
        self.__servers.remove(paramServer)

        # Check if active client is the client to be removed, if so replace it
        if self.__activeServer == paramServer:
            self.setActiveServer(self.__servers[0] if len(self.__servers) else None)


    """
            Command Methods
    """


    def createServer(self, paramTerminal, paramJoin=True, **kwargs) -> None:
        """
        Create the channel for the user
        :param paramJoin: If the client should join automatically
        :param paramTerminal: Terminal Argument
        :param kwargs: "channel_id", "secret_key", "port", "public", "join", "name"
        :return: None
        """
        # 1) Establish the necessary key word arguments
        server_kwargs = dict([(key, kwargs[key]) for key in ["channel_id", "secret_key", "port", "public"]
                              if key in kwargs])

        # 2) Create the server and save it / make it active
        server = Server(paramTerminal, **server_kwargs)
        self.addServer(server)

        if paramJoin:
            # 3) Join a client to server

            client_kwargs = dict([(key, kwargs[key]) for key in ["name"]
                                 if key in kwargs])

            client = Client(server.getTerminal(), server.getChannelID(), server.getIP()['ip'], server.getPort(),
                            server_secret=server.getSecretKey(), **client_kwargs)

            self.addClient(client)

    def deleteServer(self, channel_id=None) -> None:
        """
        Delete a channel (Server)
        :param channel_id: channel_id to be removed
        :return: None
        """

        # 1) Find the channel to delete
        selectedServer = self.getActiveServer()
        if channel_id is not None:
            for server in self.getServers():
                if server.getChannelID() == channel_id:
                    selectedServer = server
                    break
            else:
                info("MESSENGER_NO_CHANNEL", channel_id=channel_id)
                return

        if selectedServer is None:
            info("MESSENGER_NO_CHANNEL", channel_id="None")
            return

        # 2) Remove the server which will stop it and select a new active server
        self.removeServer(selectedServer)

    def joinServer(self, paramTerminal, paramChannelID, **kwargs) -> None:
        """
        Join a channel as a client
        :param paramTerminal: Terminal the channel is on
        :param paramChannelID: Channel ID
        :param kwargs: "name"
        :return: None
        """

        # 1) Check if the display name is defined
        client_kwargs = dict([(key, kwargs[key]) for key in ["name", "server_secret", "tor_port"]
                              if key in kwargs])

        # 2) Get the client from the terminal scan
        client = getClientFromTerminalScan(paramTerminal, paramChannelID, **client_kwargs)

        if client is None:
            info("MESSENGER_JOIN_FAIL", terminal=paramTerminal, channel_id=paramChannelID)
            return

        # 3) Add the client
        self.addClient(client)

    def leaveServer(self, channel_id=None) -> None:
        """
        Leave the channel
        :param channel_id: Channel to leave
        :return: None
        """
        # 1) Find the client to delete
        selectedClient = self.getActiveClient()
        if channel_id is not None:
            for client in self.getClients():
                if client.getChannelID() == channel_id:
                    selectedClient = client
                    break
            else:
                info("MESSENGER_NO_CHANNEL", channel_id=channel_id)
                return

        if selectedClient is None:
            info("MESSENGER_NO_CHANNEL", channel_id="None")
            return

        # 2) Leave the server and remove it
        self.removeClient(selectedClient)

    def activeClient(self, paramChannelID) -> None:
        """
        Set the active client
        :param paramChannelID: Channel ID
        :return: None
        """
        for client in self.getClients():
            if client.getChannelID == paramChannelID:
                self.setActiveClient(client)
                break
        else:
            info("MESSENGER_NO_CHANNEL", channel_id=paramChannelID)

    def activeServer(self, paramChannelID) -> None:
        """
        Set the active server
        :param paramChannelID: Channel ID
        :return: None
        """
        for server in self.getServers():
            if server.getChannelID == paramChannelID:
                self.setActiveServer(server)
                break
        else:
            info("MESSENGER_NO_CHANNEL", channel_id=paramChannelID)

    def sendFile(self, paramFilePath: str, channel_id: str = None) -> None:
        """
        Used to send a file to a channel
        :param paramFilePath:
        :param channel_id:
        :return: None
        """
        selectedClient = self.getActiveClient()
        if channel_id is not None:
            for client in self.getClients():
                if client.getChannelID() == channel_id:
                    selectedClient = client
                    break
            else:
                info("MESSENGER_NO_CHANNEL", channel_id=channel_id)
                return

        if selectedClient is None:
            info("MESSENGER_NO_CHANNEL", channel_id="None")
            return

        selectedClient.sendFile(paramFilePath)

    def exit(self) -> None:
        """
        Safely exit the program
        :return:
        """

        for server in self.getServers():  # Stop all servers
            if not server.getStopEvent().is_set():
                server.stopServer()

        for client in self.getClients():  # Stop all clients
            if not client.getStopEvent().is_set():
                client.leaveServer()

        sys.exit()  # Exit


    """
            Standard Methods
    """

    def mainloop(self) -> None:
        """
        Main loop for Messenger
        :return: None
        """
        while True:
            userInput = awaitInput()  # Await input from the client

            if userInput.startswith(COMMAND_KEY):  # If it is a command
                ArgumentParser(self, userInput)  # Pass to the argument parser
                continue

            if self.getActiveClient() is None:  # Send a message instead
                info("MESSENGER_NO_ACTIVE_CHANNEL")
                continue

            self.getActiveClient().sendMessage(userInput)

    @staticmethod
    def printStartMessage():
        info("MESSENGER_START")
        info("EMPTY_LINE")

        for command, (_, arguments, _) in ArgumentParser.getServerCommands().items():
            info("MESSENGER_COMMAND", command=command, arguments=arguments)
        info("EMPTY_LINE")


class ArgumentParser:
    def __init__(self, paramMessenger: Messenger, paramArgument: str):
        """
        Argument parser to transform command line to method calls
        :param paramMessenger: Messenger Application
        :param paramArgument: Console command
        """
        self.__argument: str = paramArgument
        self.__messenger: Messenger = paramMessenger

        # To be established variables
        self.__method: classmethod | None       = None  # Method to be called
        self.__args: list[Any] | None           = None  # Positional arguments
        self.__kwargs: dict[str, Any] | None    = None  # Key word arguments

        self.__expectedUsage: str | None        = None  # Usage of called command
        self.__fullUsage: str | None            = None  # Full Usage of called command

        self.parse()  # Parse the string


    """
            Getter Methods
    """

    def getArgument(self) -> str:
        """
        Get the argument supplied to the class
        :return: Argument (str)
        """
        return self.__argument

    def getMessenger(self) -> Messenger:
        """
        Get the messenger object
        :return: Messenger
        """
        return self.__messenger


    """
            Established Variables
    """

    def getMethod(self) -> classmethod | None:
        """
        Get the method to call when performing the arguments
        :return: class method or none if not found
        """
        return self.__method

    def getArgs(self) -> list[Any] | None:
        """
        The positional arguments
        :return: Positional arguments if found or none
        """
        return self.__args

    def getKwargs(self) -> dict[str, Any] | None:
        """
        Get the kwargs used when calling the method
        :return: Kwargs arguments used or None if not found
        """
        return self.__kwargs

    def getExpectedUsage(self) -> str | None:
        """
        The expected usage of the command being used
        :return: command or none if unknown
        """
        return self.__expectedUsage

    def getFullUsage(self) -> str | None:
        """
        Returns the full usage of the command
        :return: str
        """
        return self.__fullUsage

    """
            Methods
    """

    def parse(self) -> None:
        """
        Parses and performs the supplied arguments
        :return: None
        """
        # 1) Process the arguments
        try:
            self.processArguments()  # Check if it was able to split arguments (will throw exceptions)

            # Possible AssertionError
            assert self.getExpectedUsage() is not None and self.getFullUsage() is not None\
                   and self.getArgs() is not None and self.getKwargs() is not None

        except (TypeError, ValueError, IndexError, AssertionError):  # Catch Any other exception
            if self.getExpectedUsage() is not None:  # The command used is known then print that usage
                info("MESSENGER_USAGE", usage=self.getFullUsage())

            else:  # Command is not known print the help method
                info("MESSENGER_INVALID_COMMAND", command=self.getArgument())
                info("EMPTY_LINE")
                for command, (_, arguments, _) in ArgumentParser.getServerCommands().items():
                    info("MESSENGER_COMMAND", command=command, arguments=arguments)
                info("EMPTY_LINE")
            return  # Return as don't want to run any further

        # 2) Perform the arguments
        try:
            self.preformArgument()  # Perform the arguments

        except MessengerException as exception:  # Catch any exception that is thrown when method is run
            info("MESSENGER_EXCEPTION", exception=exception.message)

        except TypeError:  # When they input invalid kwargs
            info("MESSENGER_USAGE", usage=self.getFullUsage())

    def preformArgument(self) -> None:
        """
        Performs the arguments by calling the methods with args and kwargs
        :return: None
        """
        self.getMethod()(self.getMessenger(), *self.getArgs(), **self.getKwargs())

    def processArguments(self) -> None:
        """
        Process the arguments into their method, args and kwargs
        Will throw TypeError, ValueError, IndexError
        :return: If the arguments successfully processed
        """
        # Split the argument into parts | Throws TypeError
        key = self.getArgument().split(" ")[0].lower()

        # Get only parameters and not command | Throws IndexError
        arguments = " ".join(self.getArgument().split(" ")[1:])

        # Get the command attributes from server commands | Throws KeyError
        # 1) Store the method and expected usage
        self.__method, self.__expectedUsage, arg_types = self.getServerCommands().get(key)
        self.__fullUsage = f"{key} {self.getExpectedUsage()}"

        # 2) Find all positional arguments
        # Calculate the number of expected positional arguments
        numberOfPositionalArguments = len(re.findall(r"<([^>]*)>", self.getExpectedUsage()))

        # Store them as args
        self.__args = [arguments.split(" ")[index] for
                       index in range(numberOfPositionalArguments)]

        # Validate the number of positional arguments is matched
        if sum([True for pArg in self.getArgs() if pArg != '']) \
                != numberOfPositionalArguments:
            raise ValueError("Missing positional arguments")

        # 3) Establish the key word arguments
        # Use regex to find and convert kwargs to dict. Keeping a lowercase key
        self.__kwargs = dict([(g[0].lower()[1:], g[1]) for g in
                             [f[1:].split(" ") for f in re.findall(r"(\s-\w+\s+[^\s]+)", arguments)]])

        # Cast all to the correct type (str -> int, bool, etc)
        for key, value in self.getKwargs().items():
            if key in arg_types:
                arg_type = arg_types.get(key)
                self.__kwargs[key] = arg_type(value)

    @staticmethod
    def getServerCommands() -> dict:
        return {
            COMMAND_KEY + "create_server":  (Messenger.createServer, "<terminal> [-channel_id] [-secret_key] "
                                                                     "[-port] [-public] [-join] [-name]",
                                             {
                                                 "terminal": str, "channel_id": str, "secret_key": str, "port": int,
                                                 "public": bool, "join": bool, "name": str
                                             }),
            COMMAND_KEY + "delete_server":  (Messenger.deleteServer, "[-channel_id]",
                                             {
                                                 "channel_id": str
                                             }),

            COMMAND_KEY + "join_server":  (Messenger.joinServer, "<terminal> <channel_id> [-name] [-server_secret] ["
                                                                 "-tor_port]",
                                           {
                                               "terminal": str, "channel_id": str, "name": str, "tor_port": int
                                           }),

            COMMAND_KEY + "leave_server": (Messenger.leaveServer, "[-channel_id]",
                                           {
                                                "channel_id": str
                                            }),

            COMMAND_KEY + "active_server": (Messenger.activeServer, "<channel_id>",
                                            {
                                                "channel_id": str
                                            }),
            COMMAND_KEY + "active_client":  (Messenger.activeClient, "<channel_id>",
                                             {
                                                 "channel_id": str
                                             }),
            COMMAND_KEY + "send_file": (Messenger.sendFile, "<file_path> [-channel_id]",
                                        {
                                            "file_path": str, "channel_id": str
                                        }),
            COMMAND_KEY + "exit": (Messenger.exit, "", {}),
        }


if __name__ == "__main__":
    Messenger()
