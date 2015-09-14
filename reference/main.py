import sys

from reference.network.client import main

if __name__ == "__main__":
	try:
		if len(sys.argv) > 2:
			main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
		else:
			main(sys.argv[1])
	except IndexError:
		print("python -m reference.main [STUDENT_ID] [HOST?] [PORT?]")