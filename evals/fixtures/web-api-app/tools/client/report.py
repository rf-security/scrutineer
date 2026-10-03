import json
import sys
from urllib.request import urlopen


def read_status(base_url):
    with urlopen(base_url + "/status", timeout=10) as response:
        return json.load(response)


if __name__ == "__main__":
    print(read_status(sys.argv[1]))
