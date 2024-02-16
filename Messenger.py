from channel.Server import Server
from channel.Client import Client
from channel.Client import getClientFromBin
from services.terminal.TerminalScanProcess import TerminalScanService
import socket
import time
import threading

if __name__ == "__main__":
    server = Server("http://127.0.0.1:5000", public=True)

    client = Client("http://127.0.0.1:5000", server.getChannelID(), "176.35.14.162", server.getPort(),
                    client_displayName="BossMan")


    client2 = Client("http://127.0.0.1:5000", server.getChannelID(), "176.35.14.162", server.getPort(),
                     client_displayName="SpiderMan")


    client.sendMessage("Wow1")
    client2.sendMessage("Wow2")

    time.sleep(1)
    client.leaveServer()

    time.sleep(1)
    client2.sendMessage("I am the only one here")

    time.sleep(1)
    server.stop()

    time.sleep(1)

    for thread in threading.enumerate():
        print(thread)



    """
    terminalScanService = TerminalScanService("http://127.0.0.1:5000", server.getChannelID())
    terminalScanService.start()
    terminalScanService.join()

    if terminalScanService.getResult() is None:
        print("Returned None")

    client = getClientFromBin("http://127.0.0.1:5000", server.getChannelID(), terminalScanService.getResult())

    time.sleep(5)

    client.sendMessage("Hello you bitch")
    """
