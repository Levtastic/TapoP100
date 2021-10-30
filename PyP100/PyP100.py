import requests
from base64 import b64encode, b64decode
import hashlib
from Crypto.PublicKey import RSA
import time
import json
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from . import tp_link_cipher
import ast
import pkgutil
import uuid
import json

#Old Functions to get device list from tplinkcloud
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

class P100():
    _decode_params = {
        'nickname': lambda p: b64decode(p).decode('utf-8')
    }

    def __init__ (self, ipAddress, email, password):
        self.ipAddress = ipAddress
        self.terminalUUID = str(uuid.uuid4())

        self.email = email
        self.password = password

        self.errorCodes = ERROR_CODES

        self.encryptCredentials(email, password)
        self.createKeyPair()

    def encryptCredentials(self, email, password):
        #Password Encoding
        self.encodedPassword = tp_link_cipher.TpLinkCipher.mime_encoder(password.encode("utf-8"))

        #Email Encoding
        self.encodedEmail = self.sha_digest_username(email)
        self.encodedEmail = tp_link_cipher.TpLinkCipher.mime_encoder(self.encodedEmail.encode("utf-8"))

    def createKeyPair(self):
        self.keys = RSA.generate(1024)

        self.privateKey = self.keys.exportKey("PEM")
        self.publicKey  = self.keys.publickey().exportKey("PEM")

    def decode_handshake_key(self, key):
        decode: bytes = b64decode(key.encode("UTF-8"))
        decode2: bytes = self.privateKey

        cipher = PKCS1_v1_5.new(RSA.importKey(decode2))
        do_final = cipher.decrypt(decode, None)
        if do_final is None:
            raise ValueError("Decryption failed!")

        b_arr:bytearray = bytearray()
        b_arr2:bytearray = bytearray()

        for i in range(0, 16):
            b_arr.insert(i, do_final[i])
        for i in range(0, 16):
            b_arr2.insert(i, do_final[i + 16])

        return tp_link_cipher.TpLinkCipher(b_arr, b_arr2)

    def sha_digest_username(self, data):
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
        URL = f"http://{self.ipAddress}/app"
        Payload = {
            "method":"handshake",
            "params":{
                "key": self.publicKey.decode("utf-8"),
                "requestTimeMils": int(round(time.time() * 1000))
            }
        }

        r = requests.post(URL, json=Payload)

        encryptedKey = r.json()["result"]["key"]
        self.tpLinkCipher = self.decode_handshake_key(encryptedKey)

        try:
            self.cookie = r.headers["Set-Cookie"][:-13]

        except:
            errorCode = r.json()["error_code"]
            errorMessage = self.errorCodes[str(errorCode)]
            raise Exception(f"Error Code: {errorCode}, {errorMessage}")

    def login(self):
        URL = f"http://{self.ipAddress}/app"
        Payload = {
            "method":"login_device",
            "params":{
                "username": self.encodedEmail,
                "password": self.encodedPassword
            },
            "requestTimeMils": int(round(time.time() * 1000)),
        }
        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method":"securePassthrough",
            "params":{
                "request": EncryptedPayload
            }
        }

        r = requests.post(URL, json=SecurePassthroughPayload, headers=headers)

        decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

        try:
            self.token = ast.literal_eval(decryptedResponse)["result"]["token"]
        except:
            errorCode = ast.literal_eval(decryptedResponse)["error_code"]
            errorMessage = self.errorCodes[str(errorCode)]
            raise Exception(f"Error Code: {errorCode}, {errorMessage}")

    def setDeviceInfo(self, params):
        URL = f"http://{self.ipAddress}/app?token={self.token}"
        Payload = {
            "method": "set_device_info",
            "params": params,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminalUUID
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params": {
                "request": EncryptedPayload
            }
        }

        r = requests.post(URL, json=SecurePassthroughPayload, headers=headers)

        decryptedResponse = json.loads(self.tpLinkCipher.decrypt(
            r.json()["result"]["response"]))

        if decryptedResponse['error_code'] != 0:
            raise Exception(
                self.errorCodes.get(decryptedResponse['error_code'],
                                    decryptedResponse['error_code'])
            )

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
        URL = f"http://{self.ipAddress}/app?token={self.token}"
        Payload = {
            "method": "get_device_info",
            "requestTimeMils": int(round(time.time() * 1000)),
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method":"securePassthrough",
            "params":{
                "request": EncryptedPayload
            }
        }

        r = requests.post(URL, json=SecurePassthroughPayload, headers=headers)
        decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

        info = json.loads(decryptedResponse)

        if info['error_code'] != 0:
            raise Exception(
                self.errorCodes.get(info['error_code'], info['error_code'])
            )

        return info

    def getDeviceName(self):
        self.handshake()
        self.login()
        data = self.getDeviceInfo()

        data = json.loads(data)

        if data["error_code"] != 0:
            errorCode = ast.literal_eval(decryptedResponse)["error_code"]
            errorMessage = self.errorCodes[str(errorCode)]
            raise Exception(f"Error Code: {errorCode}, {errorMessage}")
        else:
            encodedName = data["result"]["nickname"]
            name = b64decode(encodedName)
            return name.decode("utf-8")
