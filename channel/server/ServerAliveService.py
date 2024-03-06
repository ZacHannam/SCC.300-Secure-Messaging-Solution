import time
from threading import Event

from Properties import ALIVE_TIMEOUT, ALIVE_TIME
from channel.server.packet.S2C_AlivePacket import AlivePacket
from channel.server.ServerConnectionService import ServerConnectionService
from channel import Service


class ServerAliveService(Service.ServiceThread):
    def __init__(self, paramServerUserList: list[ServerConnectionService], paramStopEvent: Event):
        """
        Server Alive Service to check nobody has timed out or disconnected missing a packet
        :param paramServerUserList:
        """
        super().__init__(Service.ServiceType.SERVER_ALIVE)

        self.__stop = paramStopEvent
        self.__serverUserList = paramServerUserList

    def getServerUserList(self) -> list[ServerConnectionService]:
        """
        Returns the server user list
        :return:
        """
        return self.__serverUserList

    def getStopEvent(self) -> Event:
        """
        Get the stop event
        :return: The stop event
        """
        return self.__stop

    def stop(self) -> None:
        """
        Stop the service
        :return: None
        """
        self.getStopEvent().set()

    def run_safe(self):
        alivePacket = AlivePacket()  # Create an alive packet

        while not self.getStopEvent().is_set():  # Run until the stop flag is set
            start_currentTime = int(time.time())  # Get the current time

            for user in self.getServerUserList():  # Get each user connected
                if user.getLastAliveTime() + ALIVE_TIMEOUT < start_currentTime:
                    user.kickUser("Timed out.")  # Time out if the last alive time was too long away
                    continue
                user.sendPacket(alivePacket)

            difference_currentTime: int = int(time.time()) - start_currentTime  # Get the difference in times
            self.getStopEvent().wait(ALIVE_TIME - difference_currentTime)  # Wait for the next cycle
