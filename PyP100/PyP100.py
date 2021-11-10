import requests
import hashlib
import uuid
import time
import json
import ast

from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from .tp_link_cipher import TpLinkCipher


# Old Functions to get device list from tplinkcloud
def getToken(email, password):
    URL = "https://eu-wap.tplinkcloud.com"
    Payload = {
        "method": "login",
        "params": {
            "appType": "Tapo_Ios",
            "cloudUserName": email,
            "cloudPassword": password,
            "terminalUUID": "0A950402-7224-46EB-A450-7362CDB902A2"
        }
    }

    return requests.post(URL, json=Payload).json()['result']['token']


def getDeviceList(email, password):
    URL = "https://eu-wap.tplinkcloud.com?token=" + getToken(email, password)
    Payload = {
        "method": "getDeviceList",
    }

    return requests.post(URL, json=Payload).json()


ERROR_CODES = {
    "0": "Success",
    "-1010": "Invalid Public Key Length",
    "-1012": "Invalid terminalUUID",
    "-1501": "Invalid Request or Credentials",
    "1002": "Incorrect Request",
    "-1003": "JSON formatting error "
}


class P100Error(Exception):
    pass


class P100():
    _decode_params = {
        'nickname': lambda p: b64decode(p).decode('utf-8')
    }

    def __init__(self, ipAddress, email, password, login=True):
        self._ipAddress = ipAddress
        self._terminalUUID = str(uuid.uuid4())

        self._email = email
        self._password = password

        self._errorCodes = ERROR_CODES

        self._encryptCredentials(email, password)
        self._createKeyPair()

        if login:
            self.handshake()
            self.login()

    def __getattr__(self, attr):
        try:
            return self.getParam(attr)
        except KeyError:
            pass

        raise AttributeError(
            f"'{self.__class__.__name__}' object has no attribute '{attr}'")

    def _encryptCredentials(self, email, password):
        # Password Encoding
        self._encodedPassword = TpLinkCipher.mime_encoder(
            password.encode("utf-8")
        )

        # Email Encoding
        self._encodedEmail = self._sha_digest_username(email)
        self._encodedEmail = TpLinkCipher.mime_encoder(
            self._encodedEmail.encode("utf-8")
        )

    def _createKeyPair(self):
        self._keys = RSA.generate(1024)

        self._privateKey = self._keys.exportKey("PEM")
        self._publicKey = self._keys.publickey().exportKey("PEM")

    def _decode_handshake_key(self, key):
        decode: bytes = b64decode(key.encode("UTF-8"))
        decode2: bytes = self._privateKey

        cipher = PKCS1_v1_5.new(RSA.importKey(decode2))
        do_final = cipher.decrypt(decode, None)
        if do_final is None:
            raise ValueError("Decryption failed!")

        b_arr: bytearray = bytearray()
        b_arr2: bytearray = bytearray()

        for i in range(0, 16):
            b_arr.insert(i, do_final[i])
        for i in range(0, 16):
            b_arr2.insert(i, do_final[i + 16])

        return TpLinkCipher(b_arr, b_arr2)

    def _sha_digest_username(self, data):
        b_arr = data.encode("UTF-8")
        digest = hashlib.sha1(b_arr).digest()

        sb = ""
        for i in range(0, len(digest)):
            b = digest[i]
            hex_string = hex(b & 255).replace("0x", "")
            if len(hex_string) == 1:
                sb += "0"
                sb += hex_string
            else:
                sb += hex_string

        return sb

    def handshake(self):
        URL = f"http://{self._ipAddress}/app"
        Payload = {
            "method": "handshake",
            "params": {
                "key": self._publicKey.decode("utf-8"),
                "requestTimeMils": int(round(time.time() * 1000))
            }
        }

        r = requests.post(URL, json=Payload)

        encryptedKey = r.json()["result"]["key"]
        self._tpLinkCipher = self._decode_handshake_key(encryptedKey)

        try:
            self.cookie = r.headers["Set-Cookie"][:-13]

        except (KeyError, IndexError):
            raise self._generateException(r.json()["error_code"])

    def _generateException(self, error_code):
        error_text = self._errorCodes.get(error_code, "Unknown error code")
        return P100Error(f"{error_code}: {error_text}")

    def login(self):
        URL = f"http://{self._ipAddress}/app"
        Payload = {
            "method": "login_device",
            "params": {
                "username": self._encodedEmail,
                "password": self._encodedPassword
            },
            "requestTimeMils": int(round(time.time() * 1000)),
        }
        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self._tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params": {
                "request": EncryptedPayload
            }
        }

        r = requests.post(URL, json=SecurePassthroughPayload, headers=headers)

        decryptedResponse = self._tpLinkCipher.decrypt(
            r.json()["result"]["response"]
        )

        try:
            self.token = ast.literal_eval(decryptedResponse)["result"]["token"]

        except KeyError:
            raise self._generateException(
                ast.literal_eval(decryptedResponse)["error_code"]
            )

    def setDeviceInfo(self, params):
        URL = f"http://{self._ipAddress}/app?token={self.token}"
        Payload = {
            "method": "set_device_info",
            "params": params,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self._terminalUUID
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self._tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params": {
                "request": EncryptedPayload
            }
        }

        r = requests.post(URL, json=SecurePassthroughPayload, headers=headers)

        decryptedResponse = json.loads(self._tpLinkCipher.decrypt(
            r.json()["result"]["response"]))

        if decryptedResponse['error_code'] != 0:
            raise self._generateException(decryptedResponse['error_code'])

    def setParams(self, **params):
        self.setDeviceInfo(params)

    def getParam(self, param):
        result = self.getDeviceInfo()['result'][param]

        if param in self._decode_params:
            result = self._decode_params[param](result)

        return result

    def turnOn(self):
        return self.setParams(device_on=True)

    def turnOff(self):
        return self.setParams(device_on=False)

    def setBrightness(self, brightness):
        return self.setParams(brightness=brightness)

    def getDeviceInfo(self):
        URL = f"http://{self._ipAddress}/app?token={self.token}"
        Payload = {
            "method": "get_device_info",
            "requestTimeMils": int(round(time.time() * 1000)),
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self._tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params": {
                "request": EncryptedPayload
            }
        }

        r = requests.post(URL, json=SecurePassthroughPayload, headers=headers)
        decryptedResponse = self._tpLinkCipher.decrypt(
            r.json()["result"]["response"]
        )

        info = json.loads(decryptedResponse)

        if info['error_code'] != 0:
            raise self._generateException(info['error_code'])

        return info
