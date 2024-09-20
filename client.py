'''
    file: client.py
    author: Jonathan Boyd
    mentions: SEE README.md

'''
# [ IMPORTS ]
from client_lib import login
from error_handle import exception_generator
from net_comms_lib import transmit , receive , utf8decoder
from net_sec_lib import     secure_send , secure_receive , Station 
from net_sec_lib import     Credentials, SecureKeyChain 
from net_sec_lib import     retrieve_key , share_key
import select
import server_lib as sl
import socket
import sys
# [ CONSTANT VARIABLES ]
PORT = sl.PORT
SERVER_SOCKET = sl.SERVER_SOCKET
DISCONNECT_MSG =  sl.DISCONNECT_MSG
if len(sys.argv) > 3:
    print('[ ERROR ] Invalid command line.\nsyntax: \"python client.py <SERVER IP> <SERVER PORT>\" OR \"python client.py\"')
    exit(-1)
if len(sys.argv) == 3:
    SERVER = str(sys.argv[1])
    PORT = int(sys.argv[2])
    SERVER_SOCKET = ( SERVER,PORT )
try:

    local = socket.gethostbyname( socket.gethostname() )
    client_instance = Station( alias='local_client',ip_addr=local )
    local_socket = login( SERVER=SERVER_SOCKET , max_attempts=3 )
    share_key( public_key=client_instance.keys.public_key , outbound_socket=local_socket )
    server_keyChain = SecureKeyChain( alias='SERVER' , 
                                     public_key=retrieve_key( local_socket )  ,
                                     address = local_socket )
 
except Exception as e:
    sys.stdout.write(f'\nFailure to initiate client server session... exiting.\n')
    sys.exit()

# [ BEGIN SESSION ]
prompt = '^^^(you)^^^'
fd_set = [local_socket, sys.stdin]
running = 1
while running:
    print(prompt)
    try:
        reads, writes, excepts = select.select(fd_set,[],[])
        for is_set in reads:
            # [ INPUT ]
            if is_set == sys.stdin:
                message = sys.stdin.readline()
                # [ SEND ]
                if message:
                    if message == '\n':  continue
                    try:
                        secure_send( message=message , pub_key=server_keyChain.public_key , outbound_socket=server_keyChain.address )
                        print(f'% (you): {message}')
                    except:
                        print('[ ERROR ] transmit() failed.')
                        break
                # [ DISCONNECT ]
                if message == DISCONNECT_MSG:
                    print('[ GRACEFUL EXIT ] Terminating session...')
                    running = 0
                    break
            # [ READ ]
            else:
                try:
                    message = secure_receive( inbound_socket=server_keyChain.address , priv_key=client_instance.keys.private_key )
                    if message:
                        print(f'---$$$\n\t\t\t{message}---$$$')
                    else:
                        print('[ ALERT ] Suspected server termination... exiting.')
                        running = 0;
                        break
                except:
                    print('[ ERROR ] failed to receive a transmission...exiting.')
                    running = 0
                    break
    # [ KEYBOARD INTERRUPT ]
    except KeyboardInterrupt:
        print('[ UNDESIRABLE EXIT ] Terminating session...')
        running = 0
        continue
    # [ UNKNOWN ERROR ]
    except Exception as e:
        print(f'[ ERROR ] Unknown error in session... exitng.\n{e}')
        running = 0

# [ END SESSION ]
local_socket.close()
sys.exit()

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Abhishek CSEPracticals", "Lewis Van Winkle","ArjanCodes"]

