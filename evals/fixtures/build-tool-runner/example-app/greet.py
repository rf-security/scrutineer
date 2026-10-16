import sys


def greeting(name):
    return f"Hello, {name}!"


if __name__ == "__main__":
    print(greeting(sys.argv[1] if len(sys.argv) > 1 else "world"))
