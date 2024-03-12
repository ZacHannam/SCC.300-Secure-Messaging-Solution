from flask import Flask, jsonify, request, Response
from threading import Lock
import hashlib
import os
import hmac
import base64

from Properties import TERMINAL_VERSION, CHANNEL_BIN_DIMENSIONS, CHANNEL_INFO_BIN_DIMENSIONS,\
    CHANNEL_BIN_INVALIDATE_DIMENSIONS
from utils.Base85 import intToBase85
from utils.BinarySequencer import getBinSizeBytes, Bin

TERMINAL_HMAC = os.urandom(32)

ENTRY_SIZE_B85 = int(getBinSizeBytes(CHANNEL_BIN_DIMENSIONS) * (5 / 4))


class Entry:
    def __init__(self, paramHashedSecretKey: bytes, paramInfoBin: Bin, paramChannelID: str | None):
        """
        Entry stores all information
        :param paramHashedSecretKey:
        :param paramInfoBin:
        :param paramChannelID:
        """
        self.__hmacSecretKey: int = int(hmac.new(paramHashedSecretKey, TERMINAL_HMAC,
                                                 hashlib.sha256).hexdigest(), 16)



        self.__infoBin: Bin = paramInfoBin

        self.__authHi: int = paramInfoBin.getAttribute("UNIQUE_AUTH_HI")
        self.__authLo: int = paramInfoBin.getAttribute("UNIQUE_AUTH_LO")
        self.__channelID: str | None = paramChannelID

        self.__cachedValue: dict = {}
        self.reCache()

    def getCachedValue(self) -> dict:
        """
        Cached value to be shown on terminal
        :return: Cached value (str)
        """
        return self.__cachedValue

    def getHmacSecretKey(self) -> int:
        """
        Returns the hashed secret key
        :return: secret key (bytes)
        """
        return self.__hmacSecretKey

    def getAuthHi(self) -> int:
        """
        Return Auth Hi
        :return: auth hi (int)
        """
        return self.__authHi

    def getAuthLo(self) -> int:
        """
        Return Auth Lo
        :return: auth lo (int)
        """
        return self.__authLo

    def getInfoBin(self) -> Bin:
        """
        Returns the info bin
        :return: Channel Info Bin (Bin)
        """
        return self.__infoBin

    def setInfoBin(self, paramInfoBin) -> None:
        """
        Sets the info bin
        :param paramInfoBin:
        :return: None
        """
        self.__infoBin = paramInfoBin

    def getChannelID(self) -> str | None:
        """
        Get the channel id if public
        :return: Channel ID
        """
        return self.__channelID

    def setChannelID(self, paramChannelID: str | None) -> None:
        """
        Set the channel id
        :param paramChannelID: channel id if public else None
        :return: None
        """
        self.__channelID = paramChannelID

    """
            Methods
    """

    def reCache(self) -> None:
        """
        Re caches the value on the terminal
        :return: None
        """

        channelBin: Bin = Bin(CHANNEL_BIN_DIMENSIONS)

        # Change the secret key with the terminal hmac to obscure the key
        channelBin.setAttribute("CHANNEL_SECRET_BIN", self.getHmacSecretKey())
        # Add info bin
        channelBin.setAttribute("CHANNEL_INFO_BIN", self.getInfoBin().getResult())
        self.__cachedValue = dict(( (intToBase85(channelBin.getResult(), nBytes=channelBin.getBinSizeBytes()),
                                    "Private" if self.getChannelID() is None else self.getChannelID()), ))


class Directory:
    def __init__(self):
        """
        Directory stores all of the terminal entries and presents them
        """
        self.__lock: Lock = Lock()
        self.__entries: list[Entry] = []

    """
            Getter Methods
    """

    def getLock(self) -> Lock:
        """
        Returns the lock used for concurrency control
        :return:
        """
        return self.__lock

    def getEntries(self) -> list[Entry]:
        """
        Returns all entries on the terminal
        :return:
        """
        return self.__entries

    """
            Static Methods
    """

    @staticmethod
    def validateSecretKey(paramHashedSecretKey: bytes, paramEntry: Entry) -> bool:
        """
        Validate the Secret key given against an entry
        :return: If they match
        """

        hmacSecretKey: int = int(hmac.new(paramHashedSecretKey, TERMINAL_HMAC, hashlib.sha256).hexdigest(), 16)

        return hmacSecretKey == paramEntry.getHmacSecretKey()

    """
            Methods
    """

    def findInDirectory(self, paramAuthHi: int, paramAuthLo: int) -> Entry | None:
        """
        Find a matching entry channel in the directory
        :param paramAuthHi: Auth Hi
        :param paramAuthLo: Auth Lo
        :return: Returns the entry if it finds one else None
        """

        for entry in self.getEntries():
            xor_authLo = paramAuthLo ^ entry.getAuthLo()
            xor_authHi = paramAuthHi ^ entry.getAuthHi()

            # Check if auth matches
            if xor_authLo == xor_authHi:
                return entry
        return None

    def addEntry(self, paramEntry: Entry) -> None:
        """
        Add entry to the directory
        :param paramEntry: entry to add
        :return: None
        """
        self.getEntries().append(paramEntry)

    def removeEntry(self, paramEntry: Entry):
        """
        Remove an entry from the directory
        :param paramEntry:
        :return:
        """
        self.getEntries().remove(paramEntry)

    def json(self) -> Response:
        """
        Return all all directories in json form
        :return:
        """

        str_directory = {}
        for entry in self.getEntries():
            for key, value in entry.getCachedValue().items():
                str_directory[key] = value

        return jsonify(str_directory)


app = Flask(__name__)
directory = Directory()


@app.route('/')
def home():
    return directory.json()


@app.route("/validate", methods=['POST'])
def validateChannel():
    try:
        # 1) Check if it is a post request
        if request.method != 'POST':
            raise RuntimeError(f"Invalid Method: {request.method}")

        # 2) Get the json version
        data = request.get_json()
        channel_bytes: bytes = base64.b64decode(data['CHANNEL_BYTES'])
        channelID = data['CHANNEL_ID'] if 'CHANNEL_ID' in data else None

        # 4) Check if it is correct number of bytes
        if len(channel_bytes) != getBinSizeBytes(CHANNEL_BIN_DIMENSIONS):
            raise RuntimeError("Invalid Size")

        # 5) Split into parts
        channelBin = Bin(CHANNEL_BIN_DIMENSIONS, population=channel_bytes)
        # Secret Key is the SHA-256 of the secret and Channel Info is the channel Info Bin
        secretKey: bytes = channelBin.getAttributeBytes("CHANNEL_SECRET_BIN")
        channelInfo: int = channelBin.getAttribute("CHANNEL_INFO_BIN")

        # 6) Get Channel Auth
        infoBin = Bin(CHANNEL_INFO_BIN_DIMENSIONS, population=channelInfo)
        authHi: int = infoBin.getAttribute("UNIQUE_AUTH_HI")
        authLo: int = infoBin.getAttribute("UNIQUE_AUTH_LO")

        # 7) Check for entry in directory
        entry = directory.findInDirectory(authHi, authLo)
        if entry is not None:
            validate = directory.validateSecretKey(secretKey, entry)
            if not validate:
                raise RuntimeError("Secret key is invalid!")

            entry.setInfoBin(infoBin)      # Update the channel information
            entry.setChannelID(channelID)  # Just in case they want to make it public / private
            entry.reCache()                # Re-cache the data uploaded
        else:
            directory.addEntry(Entry(secretKey, infoBin, channelID))

        return jsonify({
            "SUCCESS": True,
        })

    except RuntimeError as e:

        return jsonify({
            "SUCCESS": False,
            "EXCEPTION": str(e)
        })


@app.route("/unvalidate", methods=['POST'])
def unvalidateChannel():
    try:
        # 1) Check if it is a post request
        if request.method != 'POST':
            raise RuntimeError(f"Invalid Method: {request.method}")



        # 2) Get the json version
        data = request.get_json()
        channel_bytes: bytes = base64.b64decode(data['CHANNEL_BYTES'])

        # 4) Check if it is correct number of bytes
        if len(channel_bytes) != getBinSizeBytes(CHANNEL_BIN_INVALIDATE_DIMENSIONS):
            raise RuntimeError("Invalid Size")

        # 5) Split into parts
        channelBin = Bin(CHANNEL_BIN_INVALIDATE_DIMENSIONS, population=channel_bytes)
        # Secret Key is the SHA-256 of the secret and Channel Info is the channel Info Bin
        secretKey: bytes = channelBin.getAttributeBytes("CHANNEL_SECRET_BIN")
        authHi: int = channelBin.getAttribute("UNIQUE_AUTH_HI")
        authLo: int = channelBin.getAttribute("UNIQUE_AUTH_LO")

        # 6) Check if it exists
        entry = directory.findInDirectory(authHi, authLo)
        if entry is None:
            raise RuntimeError("Could not find channel!")

        # 7) Check for permission
        validate = directory.validateSecretKey(secretKey, entry)
        if not validate:
            raise RuntimeError("Secret key is invalid!")

        # 8) Remove the entry from the directory
        directory.removeEntry(entry)


        return jsonify({
            "SUCCESS": True
        })

    except RuntimeError as e:

        return jsonify({
            "SUCCESS": False,
            "EXCEPTION": str(e)
        })


@app.route('/status')
def status():
    version = f"TERMINAL:{TERMINAL_VERSION}"
    active = True

    return jsonify(version=version, active=active)


if __name__ == '__main__':
    app.run(debug=True)
