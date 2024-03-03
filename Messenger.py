import re
import traceback

from Properties import COMMAND_KEY
from Language import info
from channel.Client import Client, ClientException, getClientFromTerminalScan
from channel.Server import Server, ServerException


class Messenger:
    def __init__(self):
        self.activeClient = None
        self.activeServer = None
        self.clients = []
        self.servers = []

        self.printStartMessage()
        self.mainloop()

    @staticmethod
    def __awaitInput() -> str:
        print(f" > ", flush=True, end='')  # Display the initial prompt  # Ensure the prompt is displayed immediately
        user_input = input()  # Get user input
        print("\033[F\033[K", flush=True, end='')  # Move cursor up and clear the line
        return user_input

    def createChannel(self, *args, **kwargs):
        try:

            server_kwargs = dict([(key, kwargs[key]) for key in ['channel_id', "secret_key", "port", "public"]
                                  if key in kwargs])

            client_kwargs = {} if "name" not in kwargs else {"client_displayName": kwargs["name"]}
            join = kwargs['join'] if 'join' in kwargs else True

            server = Server(*args, **server_kwargs)
            self.servers.append(server)
            self.activeServer = server

            if join:
                client = Client(server.getTerminal(), server.getChannelID(), server.getIP()['ip'], server.getPort(),
                                **client_kwargs)

                self.clients.append(client)
                self.activeClient = client

        except (RuntimeError, OSError, ClientException, ServerException) as error:
            traceback.print_exc()
            info("MESSENGER_EXCEPTION", exception=error)

    def deleteChannel(self, **kwargs):
        selectedChannel: Server = self.activeServer
        if "channel_id" in kwargs:
            for channel in self.servers:
                if channel.getChannelID == kwargs.get("channel_id"):
                    selectedChannel = channel
                    break
            else:
                info("MESSENGER_NO_CHANNEL", channel_id=kwargs.get("channel_id"))

        if selectedChannel is not None:
            try:
                selectedChannel.stopServer()
                self.servers.remove(selectedChannel)
                self.activeServer = None if len(self.servers) < 1 else self.servers[0]
            except (RuntimeError, OSError) as error:
                info("MESSENGER_EXCEPTION", exception=error)
        else:
            info("MESSENGER_NO_CHANNEL", channel_id=kwargs.get("channel_id"))

    def joinChannel(self, paramTerminal, paramChannelID, **kwargs):
        try:
            name = None if "name" not in kwargs else kwargs["name"]

            client = getClientFromTerminalScan(paramTerminal, paramChannelID, client_displayName=name)

            if client is None:
                info("MESSENGER_JOIN_FAIL", terminal=paramTerminal, channel_id=paramChannelID)

            self.clients.append(client)
            self.activeClient = client

        except (RuntimeError, OSError) as error:
            info("MESSENGER_EXCEPTION", exception=error)

    def leaveChannel(self, **kwargs):
        selectedChannel: Client = self.activeClient
        if "channel_id" in kwargs:
            for channel in self.clients:
                if channel.getChannelID == kwargs.get("channel_id"):
                    selectedChannel = channel
                    break
            else:
                info("MESSENGER_NO_CHANNEL", channel_id=kwargs.get("channel_id"))

        if selectedChannel is not None:
            try:
                selectedChannel.leaveServer()
                self.clients.remove(selectedChannel)
                self.activeClient = None if len(self.clients) < 1 else self.clients[0]
            except (RuntimeError, OSError) as error:
                info("MESSENGER_EXCEPTION", exception=error)
        else:
            info("MESSENGER_NO_CHANNEL", channel_id=kwargs.get("channel_id"))

    def activeChannel(self, paramChannelID):
        for channel in self.clients:
            if channel.getChannelID == paramChannelID:
                self.activeClient = channel
                break
        else:
            info("MESSENGER_NO_CHANNEL", channel_id=paramChannelID)

    def activeServer(self, paramChannelID):
        for server in self.servers:
            if server.getChannelID == paramChannelID:
                self.activeServer = server
                break
        else:
            info("MESSENGER_NO_CHANNEL", channel_id=paramChannelID)

    def banUser(self, paramUserName, **kwargs):
        selectedChannel: Server = self.activeServer
        if "channel_id" in kwargs:
            for channel in self.servers:
                if channel.getChannelID == kwargs.get("channel_id"):
                    selectedChannel = channel
                    break
            else:
                info("MESSENGER_NO_CHANNEL", channel_id=kwargs.get("channel_id"))

        if selectedChannel is not None:
            try:
                try:
                    selectedChannel.banUser(paramUserName)
                    info("BANNED_USER", user_name=paramUserName)
                except ClientException:
                    info("FAILED_BANNED_USER", user_name=paramUserName)
            except (RuntimeError, OSError) as error:
                info("MESSENGER_EXCEPTION", exception=error)
        else:
            info("MESSENGER_NO_CHANNEL", channel_id=kwargs.get("channel_id"))

    def mainloop(self):
        while True:
            userInput = self.__awaitInput()

            if userInput.startswith(COMMAND_KEY):
                ArgumentParser(self, userInput)
                continue

            if self.activeClient is None:
                info("MESSENGER_NO_ACTIVE_CHANNEL")
                continue

            self.activeClient.sendMessage(userInput)




    @staticmethod
    def printStartMessage():
        info("MESSENGER_START")
        info("EMPTY_LINE")

        for command, (_, arguments, _) in ArgumentParser.getServerCommands().items():
            info("MESSENGER_COMMAND", command=command, arguments=arguments)
        info("EMPTY_LINE")


class ArgumentParser:
    def __init__(self, paramMessenger: Messenger, paramArgument: str):
        self.__argument = paramArgument

        if not self.__processArguments():
            return

        try:
            self.preformArgument(paramMessenger)
        except Exception as exception:
            info("MESSENGER_EXCEPTION", exception=str(exception))

    def preformArgument(self, paramMessenger: Messenger):
        self.getMethod()(paramMessenger, *self.getPositionalArgs(), **self.getKeyWordArgs())

    def __getArgument(self):
        return self.__argument

    def __processArguments(self) -> bool:
        try:
            key = self.__getArgument().split(" ")[0].lower()
            arguments = " ".join(self.__getArgument().split(" ")[1:]).lower()
            method, command_arguments, arg_types = self.getServerCommands().get(key)
        except (IndexError, KeyError):
            raise RuntimeError()  # TO-DO chat instead

        self.__method = method

        self.__key_word_args = dict([(g[0], g[1]) for g in
                                     [f[1:].split(" ") for f in re.findall(r"(-\w+\s+\w+)", arguments)]])

        for key, value in self.__key_word_args.items():
            if key.lower() in arg_types:
                arg_type = arg_types.get(key.lower())
                self.__key_word_args[key] = arg_type(value)

        numberOfPositionalArguments = len(re.findall(r"<([^>]*)>", command_arguments))

        self.__positional_args = [arguments.split(" ")[index] for
                                  index in range(numberOfPositionalArguments)]

        if sum([True for pArg in self.__positional_args if pArg != '']) \
                == numberOfPositionalArguments:
            return True

        info("MESSENGER_USAGE", usage=command_arguments)
        return False

    def getMethod(self):
        return self.__method

    def getKeyWordArgs(self) -> dict:
        return self.__key_word_args

    def getPositionalArgs(self) -> list:
        return self.__positional_args

    @staticmethod
    def getServerCommands() -> dict:
        return {
            COMMAND_KEY + "create_channel": (Messenger.createChannel, "<terminal> [-channel_id] [-secret_key] "
                                                                      "[-port] [-public] [-join] [-name]",
                                             {
                                                 "terminal": str, "channel_id": str, "secret_key": str, "port": int,
                                                 "public": bool, "join": bool, "name": str
                                             }),
            COMMAND_KEY + "delete_channel": (Messenger.deleteChannel, "[-channel_id]",
                                             {
                                                 "channel_id": str
                                             }),

            COMMAND_KEY + "join_channel": (Messenger.joinChannel, "<terminal> <channel_id> [-name]",
                                           {
                                               "terminal": str, "channel_id": str, "name": str
                                           }),

            COMMAND_KEY + "leave_channel": (Messenger.leaveChannel, "[-channel_id]",
                                            {
                                                "channel_id": str
                                            }),

            COMMAND_KEY + "active_server": (Messenger.activeServer, "<channel_id>",
                                            {
                                                "channel_id": str
                                            }),
            COMMAND_KEY + "active_channel": (Messenger.activeChannel, "<channel_id>",
                                             {
                                                 "channel_id": str
                                             }),

            COMMAND_KEY + "ban_user": (Messenger.banUser, "<user_name> [-channel_id]",
                                       {
                                           "user_name": str, "channel_id": str
                                       }),

        }


if __name__ == "__main__":
    Messenger()

    """
    server = Server("http://127.0.0.1:5000", public=True)

    client = Client("http://127.0.0.1:5000", server.getChannelID(), "176.35.14.162", server.getPort(),
                    client_displayName="BossMan")
    
    client2 = Client("http://127.0.0.1:5000", server.getChannelID(), "176.35.14.162", server.getPort(),
                     client_displayName="SpiderMan")
    
    client.sendMessage("Wow1")
    # client2.sendMessage("Wow2")

    # client.leaveServer()

    # client2.sendMessage("I am the only one here")

    time.sleep(1)
    server.stop()

    time.sleep(1)

    for thread in threading.enumerate():
        print(thread)

    terminalScanService = TerminalScanService("http://127.0.0.1:5000", server.getChannelID())
    terminalScanService.start()
    terminalScanService.join()

    if terminalScanService.getResult() is None:
        print("Returned None")

    client = getClientFromBin("http://127.0.0.1:5000", server.getChannelID(), terminalScanService.getResult())

    time.sleep(5)

    client.sendMessage("Hello you bitch")
    """
