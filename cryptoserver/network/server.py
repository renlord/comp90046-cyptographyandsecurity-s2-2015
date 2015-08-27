# COMP90043 Cryptography and Security Root Server Implementation
# University of Melbourne
# For use in Project 
# 
# Commissioned by Prof. Assoc. Udaya P.
# Authored by Renlord Y.
# 
# 23 Jul 2015

import os
import socket as s
from multiprocessing import Process

from cryptoserver.network.worker import worker

# OpenSSL Generated DH Params
GENERATOR = 5
# 2048 Bit Long Prime
PRIME = 0x009415e694593f5929982e48a4d3ddc5a11cede5df458d2dd180c6a11262bdacdc9608d84fc18452d81b8f8e848209fdd4e1efc39977e76b92ee759aba20151ce9ecb6f88f172fc600557af47acf651718d55d16fd66d694fbb32cf34d01302f2d08d55d98372ac6486e871c448081bc6b8a7bd8cf0580866b26b24a4090b40837c0aab70c2e453250157cf0deaba4a4f2f70fcb4455c6bb269203d4b3e9c47ad46751de03db727bd002baf74626ebfbae8ff64c5d165434b8b0ca1f03ef463e72c5dc616e09d8f0cf49aa6b5f50f8410297154ef4999662221138d3b7e20827cc43f0621754ed89f469e038f95fe7a2303c3d3eb5da4f5dfb04a49ad269a896fb

def main(): 
    clientProcesses = []

    socket = s.socket()
    socket.bind(('', 8001))
    socket.listen(10)

    while True:
        print("COMP90043 Cryptography and Security Project Server Initiated. Root Process {0}".format(os.getpid()))
        client, _ = socket.accept()
        p = Process(target=worker, args=(client, GENERATOR, PRIME))
        p.start()
        clientProcesses.append(p)
        client.close()

if __name__ == "__main__":
    main()
