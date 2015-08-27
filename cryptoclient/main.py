from cryptoclient.network.client import main
import sys

if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except IndexError:
        print("python client.py [STUDENT_ID] [HOST?] [PORT_NO?]")