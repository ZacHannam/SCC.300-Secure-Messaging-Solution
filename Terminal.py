from flask import Flask, jsonify, request, Response
from threading import Lock
import hashlib
import os
import hmac

from Properties import CHANNEL_BIN_DIMENSIONS, CHANNEL_INFO_BIN_DIMENSIONS
from utils.codecs.Base85 import base85ToInt, intToBase85, BASE_85_ALPHABET
from utils.BinarySequencer import getBinSize, Bin

TERMINAL_VERSION = "beta0.1"  # Do not change
TERMINAL_HMAC = os.urandom(32)  # Should be saved in database

ENTRY_SIZE_B85 = int((getBinSize(CHANNEL_BIN_DIMENSIONS) // 8) * (5 / 4))


class Entry:
    def __init__(self, paramChannel: str, channel_id=None):
        assert len(paramChannel) == ENTRY_SIZE_B85

        # Original channel id
        self.__channel_bin = Bin(CHANNEL_BIN_DIMENSIONS,
                                 population=base85ToInt(paramChannel))

        secret_key = self.__channel_bin.getAttribute("CHANNEL_SECRET_BIN")
        secret_key_bytes = secret_key.to_bytes(self.__channel_bin.getAttributeSize("CHANNEL_SECRET_BIN") // 8,
                                               byteorder="big", signed=False)

        # Change the secret key with the terminal hmac to obscure the key
        # In case the secret key being used is common
        self.__channel_bin.setAttribute("CHANNEL_SECRET_BIN", int(hmac.new(secret_key_bytes,
                                                                           TERMINAL_HMAC,
                                                                           hashlib.sha256).hexdigest(),
                                                                  16))

        # Convert back into base85
        self.__channel = intToBase85(self.__channel_bin.getResult())
        self.__channelID = channel_id

    """
            Getter Methods
    """

    def getChannel(self) -> str:
        return self.__channel

    def getChannelID(self) -> str:
        return self.__channelID

    def getChannelBin(self) -> Bin:
        return self.__channel_bin

    def getChannelInfoBin(self) -> Bin:
        return Bin(CHANNEL_INFO_BIN_DIMENSIONS,
                   population=self.__channel_bin.getAttribute("CHANNEL_INFO_BIN"))

    """
            Methods
    """

    def validateSecretKey(self, paramSecretKey: str) -> bool:
        entry_secretKey = self.getChannelBin().getAttribute("CHANNEL_SECRET_BIN")
        entry_secretKeySize = self.getChannelBin().getAttributeSize("CHANNEL_SECRET_BIN") // 8

        secret_key = hmac.new(
            hashlib.sha256(paramSecretKey.encode()).digest(),
            TERMINAL_HMAC,
            hashlib.sha256).digest()

        return hmac.compare_digest(entry_secretKey.to_bytes(entry_secretKeySize, byteorder="big", signed=False),
                                   secret_key)


class Directory:
    def __init__(self):
        self.__lock = Lock()
        self.__directory = {}

    """
            Getter Methods
    """

    def __getLock(self) -> Lock:
        return self.__lock

    def __getDirectory(self) -> dict:
        return self.__directory

    """
            Methods
    """

    def json(self) -> Response:

        str_directory = {}
        for key, entry in self.__getDirectory().items():
            str_directory[key] = "Private" if entry.getChannelID() is None else entry.getChannelID()

        return jsonify(str_directory)

    """
            Entry Methods
    """

    def __validateEntry(self, paramChannelInfoBin: Bin) -> Entry | None:

        uniqueAuth_LO, uniqueAuth_HI = paramChannelInfoBin.getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")

        with self.__getLock():
            for directory_channel in self.__getDirectory().values():

                directoryAuth_LO, directoryAuth_HI = directory_channel.getChannelInfoBin() \
                    .getAttribute("UNIQUE_AUTH_LO", "UNIQUE_AUTH_HI")

                if uniqueAuth_LO ^ directoryAuth_LO == uniqueAuth_HI ^ directoryAuth_HI:
                    return directory_channel
        return None

    def __addEntry(self, paramChannel, channel_id=None) -> None | Entry:
        entry = Entry(paramChannel, channel_id=channel_id)
        self.__getDirectory()[entry.getChannel()] = entry
        return entry

    def addEntry(self, paramChannel: str, channel_secret=None, channel_id=None) -> None | Entry:
        assert len(paramChannel) == ENTRY_SIZE_B85

        # Channel bin from the channel id
        channel_bin = Bin(CHANNEL_BIN_DIMENSIONS,
                          population=base85ToInt(paramChannel))

        # Channel info bin from the channel bin
        channel_info_bin = Bin(CHANNEL_INFO_BIN_DIMENSIONS,
                               population=channel_bin.getAttribute("CHANNEL_INFO_BIN"))

        duplicate_entry = self.__validateEntry(channel_info_bin)

        with self.__getLock():
            if duplicate_entry is None:
                return self.__addEntry(paramChannel, channel_id=channel_id)

            if channel_secret is None or not duplicate_entry.validateSecretKey(channel_secret):
                raise RuntimeError(f"Channel already exists: {paramChannel}")

            del self.__getDirectory()[duplicate_entry.getChannel()]
            return self.__addEntry(paramChannel, channel_id=channel_id)

    def removeEntry(self, paramSecretKey: str) -> bool:

        with self.__getLock():
            for key, entry in self.__getDirectory().items():
                if entry.validateSecretKey(paramSecretKey):
                    del self.__getDirectory()[key]
                    return True

            return False


app = Flask(__name__)
directory = Directory()


@app.route('/')
def home():
    return directory.json()


@app.route("/validate", methods=['POST'])
def validateChannel():
    try:
        if request.method != 'POST':
            raise RuntimeError(f"Invalid Method: {request.method}")

        data = request.get_json()
        channel = data['CHANNEL']

        # Check if there are any illegal characters
        for character in channel:
            if character not in BASE_85_ALPHABET:
                raise RuntimeError(f"Invalid Character: {character}")

        # Check size of channel
        if len(channel) != ENTRY_SIZE_B85:
            raise RuntimeError(f"Invalid length: {len(channel)}")

        channelID = data['CHANNEL_ID'] if 'CHANNEL_ID' in data else None
        channelSecret = data['CHANNEL_SECRET'] if 'CHANNEL_SECRET' in data else None

        entry = directory.addEntry(channel, channel_id=channelID, channel_secret=channelSecret)

        return jsonify({
            "SUCCESS": True,
            "CLIENT": entry.getChannel()
        })

    except RuntimeError as e:

        return jsonify({
            "SUCCESS": False,
            "EXCEPTION": str(e)
        })


@app.route("/unvalidate", methods=['POST'])
def unvalidateChannel():
    try:
        if request.method != 'POST':
            raise RuntimeError(f"Invalid Method: {request.method}")

        data = request.get_json()
        secretKey = data['CHANNEL_SECRET']

        response = directory.removeEntry(secretKey)
        if not response:
            raise RuntimeError(f"Failed to find channel with secret key: {secretKey}")

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
