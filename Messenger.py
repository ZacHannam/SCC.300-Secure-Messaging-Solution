from channel.Server import Server
from channel.Client import Client
from channel.Client import getClientFromBin
from services.terminal.TerminalScanProcess import TerminalScanService
import socket
import time

if __name__ == "__main__":
    server = Server("http://127.0.0.1:5000", channel_id="Backus", secret_key="Cool", public=True)


    """
    client = Client("http://127.0.0.1:5000", server.getChannelID(), socket.gethostname(), server.getPort(),
                    client_displayName="BossMan")
    """

    """
    terminalScanService = TerminalScanService("http://127.0.0.1:5000", "B")
    terminalScanService.start()
    terminalScanService.join()

    if terminalScanService.getResult() is None:
        print("Returned None")

    client = getClientFromBin("http://127.0.0.1:5000", "B", terminalScanService.getResult())
    """

    """
    time.sleep(5)

    client.sendMessage("".join(["a" for _ in range(501)]))
    """

    """
    client2 = Client("http://127.0.0.1:5000", server.getChannelID(), socket.gethostname(), server.getPort(),
                     client_displayName="SpiderMan")
    """
