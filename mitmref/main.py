import os

from mitmref.network.client import main

if __name__ == "__main__":
	try:
        if len(sys.argv) > 2:
            main(sys.argv[1], sys.argv[2], sys.argv[3])
        else:
            main(sys.argv[1])
    except IndexError:
        print("python client.py [DEST_HOST] [DEST_PORT] [LISTEN_PORT?]")