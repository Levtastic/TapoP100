# Tapo P100
Tapo P100 is a Python library for controlling the Tp-link Tapo P100 plugs, P105 plugs and L510E bulbs.
This version of the repo has been heavily modified to suit [Levtastic](https://github.com/Levtastic)'s needs.
The original repo can be found at https://github.com/fishbigger/TapoP100

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install PyP100.

```bash
pip3 install git@github.com:Levtastic/TapoP100.git
```

## Usage

```python
import PyP100

p100 = PyP100.P100("192.168.X.X", "email@gmail.com", "Password123")  # Creating a P100 plug object

p100.getDeviceInfo() # Returns dict with all the device info

if p100.device_on:  # Check if the device is currently on
    p100.turnOff()  # Sends the turn off request
else:
    p100.turnOn()  # Sends the turn on request
    p100.setBrightness(100)  # Sends the set brightness request


```

## Contributers
[fishbigger](https://github.com/fishbigger)\
[K4CZP3R](https://github.com/K4CZP3R)\
[Sonic74](https://github.com/sonic74)

## License
[MIT](https://choosealicense.com/licenses/mit/)
