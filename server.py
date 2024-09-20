
'''
    file: server.py
    author: Jonathan Boyd
    mentions: SEE README.md

'''
# [ IMPORTS ]
from cryptography.hazmat.primitives.asymmetric import rsa
from dataclasses import dataclass , field
from error_handle import exception_generator
from net_sec_lib import secure_broadcast , secure_receive , retrieve_key
from net_sec_lib import SecureKeyChain, KeyRing, Station , share_key
import select
import server_lib as sl
import socket
import sys
# ==============================================================================================


# [ CONSTANT VARIABLES ]
LOCALHOST = sl.SERVER
SERVER_SOCKET = sl.SERVER_SOCKET
MAX_CLIENTS = sl.MAX_CLIENTS
DISCONNECT_MSG = sl.DISCONNECT_MSG

# [ OPEN AND MARK SERVER LOG ]
log = sl.Log(userid='12345',username='Jane Doe')
logger = sl.generate_logger( logger=log )

# [ VALIDATE COMMAND LINE ARGUMENT ]
if len(sys.argv) > 2:
    logger('[ ERROR ] Command line error...\nsyntax: \"python server.py <PORT>\" OR \"python server.py\"')
    exit(-1)
if len(sys.argv) == 1:
    PORT = sl.PORT
    logger( f'[ NOTIFICATION ] using default port:{PORT}')
else:
    PORT = sys.argv[1]
    logger( f'[ NOTIFICATION ] using user-defined port:{PORT}')
    SERVER_SOCKET = (sl.SERVER,int(PORT))

# [ SERVER INSTANTIATION ]
logger( f'~~[ (0) BOOT ] Server running... address:{LOCALHOST}.')

logger( '[ (1) SOCKET - ATTEMPT ] socket().')
try:
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger( '[ (1) SOCKET - SUCCESS ]...  success.')
except Exception as e:
    logger( f'[(1) [ ERROR) ] SOCKET - FAILURE...exiting.\n{e}')
    exit(-1)

logger( '[ (2) BIND - ATTEMPT ] bind().')
try:
    listen_socket.bind(SERVER_SOCKET)
    logger( '[ (2) BIND - SUCCESS ]... success.')
except Exception as e:
    logger( f'[(2) [ ERROR ] BIND - FAILURE...exiting.\n{e}')
    listen_socket.close()
    exit(-1)

logger( '[ (3) LISTEN - ATTEMPT ] listen().')
try:
    listen_socket.listen(MAX_CLIENTS)
    logger( '[ (3) LISTEN - SUCCESS ]... success.')
except Exception as e:
    logger( f'[(3) [ ERROR ] LISTEN - FAILURE...exiting.\n{e}')
    listen_socket.close()
    exit(-1)

logger( f'~~[ (4) LOAD ] server creating data handlers...')
connection_ledger = sl.ActiveConnectionLedger(listener=listen_socket)
user_database = sl.Database()
server_instance = Station(alias='SERVER',ip_addr=LOCALHOST)
logger( f'~~[ (4) LOAD ] server successfully created data handlers...')

logger( f'~~[ (5) INIT ] server in operation...')
# [ BEGIN SESSION ]
print('\t\t\t', end='')
print('WELCOME')
print('\t\t\t', end='')
print('ENTER \'shutdown\' to terminate the server session.')
print('\t\t\t', end='')
print('ENTER \'audit\' to print database statistics to the audit file.')
print('\t\t\t', end='')
print('')
print('\t\t\t', end='')
print('Creator : Jonathan Boyd')
print('\t\t\t', end='')
print('\n\n')
terminate_session = 0
while not terminate_session:
    try:
        reads, _ , _ = select.select(connection_ledger.manager.fd_set,[],[])
        for is_set in reads:
            # [ AUTHENTICATION ]
            if is_set == connection_ledger.manager.listen_socket:
                try:
                    client = sl.srv_accept_client(connection_socket=connection_ledger.manager.listen_socket)
                    logger( f'[ CONNECTION - ATTEMPT ] accepting new connection @{client.client.ip_addr}')
                    sl.srv_connect_client(client=client, connection_ledger=connection_ledger, database=user_database)
                    sl.srv_welcome_client( client=client )
                    # [ receive client public key ]
                    connection_ledger.update_key( connection=client.csocket , key=retrieve_key( client.csocket ) )
                    # [ send client the server public key ]
                    share_key( public_key=server_instance.keys.public_key , outbound_socket=client.csocket )
                    logger( f'[ CONNECTION - SUCCESS ] accepted new connection @{client.client.ip_addr}: Alias - {client.client.alias}')
                    logger( f'[ STATUS ] clients connected: {connection_ledger.database.user_count}')
                
                    if connection_ledger.database.user_count > 0:
                        group = [ 
                                    SecureKeyChain(
                                        alias=connection_ledger.database.user_set[x].alias,
                                        public_key=connection_ledger.database.user_set[x].public_key,
                                        address=x )
                                     for x in connection_ledger.database.user_set.keys()
                                ]
                        secure_broadcast(message='[ CONNECTED ]', 
                                            sender=client.client.alias , 
                                            group=group )
                except Exception as e:
                    logger( f'[ ERROR ] failure in user authentication.\n{e}')
                    break
            # [ SERVER COMMAND ]
            elif is_set == sys.stdin:
                try:
                    command = sys.stdin.readline()
                    if command == 'shutdown\n':
                        logger( '[ COMMAND ] shutdown command executed... terminating server session.')
                        if connection_ledger.database.user_count > 0:
                            group = [ 
                                     SecureKeyChain(
                                         alias=connection_ledger.database.user_set[x].alias,
                                         public_key=connection_ledger.database.user_set[x].public_key,
                                         address=x )
                                     for x in connection_ledger.database.user_set.keys()
                                     ]
                            secure_broadcast(message='[ ALERT ] Server shutting down...', 
                                            sender=server_instance.alias , 
                                            group=group )
                            active_connections = [ 
                                                  connection_ledger.database.user_set[x].alias for x in
                                                  connection_ledger.database.user_set.keys()]
                            user_database.purge(users=active_connections)
                            connection_ledger.purge()
                        terminate_session = 1
                        break
                    elif command == 'audit\n':
                        user_database.audit()
                except Exception as e:
                    logger(f'[ ERROR ] Server command failure...\n{e}')
                    break
            # [ EXTERNAL MESSAGE RECEIVED ]
            else:     
                try:
                    message = secure_receive(inbound_socket=is_set , priv_key=server_instance.keys.private_key )
                    username = connection_ledger.database.user_set[is_set].alias 
                    group = [ 
                                SecureKeyChain(
                                    alias=connection_ledger.database.user_set[x].alias,
                                    public_key=connection_ledger.database.user_set[x].public_key,
                                    address=x )
                                for x in connection_ledger.database.user_set.keys() if
                                x != is_set
                            ]
                    # [ client disconnecting ]
                    if not message or message == DISCONNECT_MSG:
                        logger( f'[ ALERT ] client {connection_ledger.database.user_set[is_set].alias} is disconnecting.')
                        user_database.purge(users=[connection_ledger.database.user_set[is_set].alias])
                        connection_ledger.remove(connection=is_set)
                        is_set.close() 
                        secure_broadcast( message='[ DISCONNECTED ]' , sender=username , group=group )
                        logger( f'[ STATUS ] clients connected: {connection_ledger.database.user_count}')
                    # [ client broadcasting ]
                    else:
                        stats = [
                                    ('successful_broadcast_count',1)
                                ]
                        user_database.update_stats( username=username , stats=stats )
                        secure_broadcast( message=message , sender=username , group=group )
                except Exception as e:
                    logger( f'[ ERROR ] error in message reception.\n{e}')
                    break
    except KeyboardInterrupt:
        logger( '[ UNDESIRABLE EXIT ] Terminating session.')
        break
    except:
        logger( '[ ERROR ] Unknown error in session... exitng.')
        break
# [ END PROCESS ]
# ============================================================================================================
user_database.save()
connection_ledger.manager.listen_socket.close()
logger('EXIT')
sys.exit()

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Abhishek CSEPracticals", "Lewis Van Winkle","ArjanCodes"]
