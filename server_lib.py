#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    Module <- SERVER_LIB

    Author: Jonathan Boyd
    Context: Network Programming : Client Server ( Server - Side )

    Provides server management and authentication functionality for
    client server model.

    Project Inception: 09/08/2024

    Mentions: Errors are accompanied by exceptions specifying the source trail if caught.

    Classes         :
        
        Log                     
        Client
        Connection
        ConnectionMultiplexor
        UserIndex
        ActiveConnectionLedger

    Functions       :

        srv_welcome_client( * , client : Connection )
        srv_get_credentials( * , client : Connection )
        srv_user_authenticate( * , client : Connection, database : Database ) -> str:
        srv_connect_client( * , client : Connection , connection_ledger : ActiveConnectionLedger,  database : Database)
        srv_accept_client( * , connection_socket : socket ) -> Connection :

    Constants       :

        SERVER          <- server-admin specified ip address of server
        PORT = 8080     <- server-admin specified service port of server
        SERVER_SOCKET   <- server-admin specified ip address and port pairing
        MAX_CLIENTS     <- server-admin specified maximum connection queue size
        DISCONNECT_MSG  <- server-admin specified client disconnect keyword
        SERVER_GREETING <- server-admin specified welcome message for connecting clients

    Dependencies    :

        Custom modules ...
            database_lib
            error_handle
            net_comms_lib
            net_sec_lib

        Well-known modules ...
            collections.abc
            cryptography
            dataclasses
            socket
            sys
'''
# [ IMPORT ]
from collections.abc import Callable
from cryptography.hazmat.primitives.asymmetric import rsa
from database_lib import Database
from dataclasses import dataclass, field
from error_handle import exception_generator
from net_comms_lib import transmit, receive , utf8decoder
from net_sec_lib import Credentials , hashed_passwd , key_stringToRSA
import socket
import sys
# [ CONSTANTS ]
# Server IPv4 address: ...
SERVER = socket.gethostbyname(socket.gethostname())
# Ephem port: 8080
PORT = 8080
SERVER_SOCKET = (SERVER,PORT)
# Maximum acceptable clients: 5
MAX_CLIENTS = 5
# Disconnection message
DISCONNECT_MSG = 'disconnect\n'
# Server welcome message
SERVER_GREETING = '\t\t\t\tWelcome to the Chat Room!\n\n\t\t\t\tBe respectful and be sure to type\n\t\t\t\tdisconnect to exit the chat.'

# [ CLASS ]
# Server logging
class Log:
    ''' 
        Logs server activity to a log file in a configured format.

        This class is coupled with the error_handle module ( exception_generator ).

            Fields  :
            
                __log_file      <-  location of log output
                __userid        <-  numerical alias of active server admin
                __username      <-  common name alias of active server admin
                __log_index     <-  indexor of active log session

            Constructors    :
                Log( userid : str , username : str , log_file ) <- [ all parameters optional ]
                    <- Opens log file and appends identification upon instantiation.
            
            Methods         :

                logging
    '''
    def __init__(self, userid : str ='N/A', username : str ='N/A', log_file : str  ='output.txt') -> None :
        ''' 
            Constructor <- ( See class Log overview documentation in this module. )
        
            This function is coupled with the error_hanle module ( exception_genertor )
    
            Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.__log_file = log_file
            self.__userid = userid
            self.__username = username
            self.__log_index = 0
            with open(self.__log_file,'a') as log_handle:
                log_handle.write(f'ID : {self.__userid} NAME : {self.__username} \n')
        except Exception as e :
            raise Exception(exception_generator(e))

    def logging(self, message : str) -> None :
        ''' 
            Writes a provided message to the __log_file file.

            This function is coupled with the error_handle module ( exception_generator )

                Parameters  :

                    message : str   <- the message to be logged
                
                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            with open(self.__log_file,'a') as log_handle:
                log_handle.write(f'log [{self.__log_index}] >> {message}\n')
            self.__log_index += 1
        except Exception as e :
            raise Exception(exception_generator(e))

@dataclass( kw_only=True )
class Client:
    ''' 
        Stores client metadata  required for communication.
        
        This class is coupled with the cryptography module.

        Constructors    :
            (KW_ONLY)
            Client( alias : str . ip_addr : str , public_key : RSAPublicKey )

    '''
    alias       : str
    ip_addr     : str
    public_key  : rsa.RSAPublicKey  = field( default=None , init=False)


class Connection:
    '''
        Maintains information corresponding to a client connection and client metadata.

        This class is coupled with the Client class ( ** local class ** )
        This class is coupled with the socket module.
        This class is coupled with the error_handle module ( exception_generator )

        Constructors    :
            (KW_ONLY)
            Connection( csocket : socket , ip_addr : str)

        Fields          :
        
            csocket : socket    <- network socket associated with a connection
            client  : Client    <- ( See Client class overview documentation in this module. )

    '''
    csocket : socket
    client  : Client

    def __init__( self , * , csocket : socket ,  ip_addr : str ) -> None :
        ''' 
            Constructor <- ( See Connection class overiew in this module. )

            This function is coupled with the socket module.
            This function is coupled with the Client class ( ** local class ** ).
            This function is coupled with the error_handle module ( exception_generator )
            
            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.csocket = csocket
            self.client = Client(alias='',ip_addr=ip_addr)
        except Exception as e :
            raise Exception(exception_generator(e))

    def update_alias( self , * , name : str ) -> None :
        ''' 
        Updates the alias tied to a given connection instance.

        This function is coupled with the error_handle module ( exception_generator )
                
                Parameters (KW_ONLY) :
                    
                    name : str  <- prescribed alias

                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.client.alias = name
        except Exception as e :
             raise Exception(exception_generator(e))

@dataclass
class ConnectionMultiplexor:
    ''' 
        Facilitates socket multiplexing. Maintains a dynamic file descriptor set for socket
        select functionality.

        This class is coupled with the dataclasses module.
        This class is coupled with the socket module.
        This class is coupled with the error_handle module ( exception_generator ).

            Constructors :
                ConnectionMultiplexor(listen_socket : socket)     <- Requires the socket designated for
                                                                    receiving new client connections.
            Fields :
                
                listen_socket   : socket        <- socket designated for detecting new client connections
                fd_set          : list[socket]  <- list of currently maintained connection sockets

                ** __post_init__() defined  <- adds stdin and listen socket to the file descriptor set

    '''
    listen_socket   : socket
    fd_set          : list[socket] = field( default_factory=list)
    def __post_init__(self):
        ''' 
            ( See ConnectionMultiplexor class overview documentation in this module. )
            
            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.fd_set.append(sys.stdin)
            self.fd_set.append(self.listen_socket)
        except Exception as e:
            raise Exception(exception_generator(e))


@dataclass
class UserIndex:
    ''' 
        Maintains a neutrally defined user dictionary with an accompanying user count variable.

        This class is coupled with the dataclasses module.

            Constructors :
                
                UserIndex()     <- Default

            Fields      :
                
                user_set    : dict      <- maintains a set of users and desired metadata
                user_count  : int       <- denotes number of users in user_set

    '''
    user_set        : dict  =   field(default_factory=dict,init=False)
    user_count      : int   =   field(default=0, init=False)

class ActiveConnectionLedger:
    ''' 
        Actively monitors and manages network socket connections.

        This class is coupled with the socket module.
        This class is coupled with the ConnectionMultiplexor class ( ** local class ** ).
        This class is coupled with the UserIndex class ( ** local class ** ).
        This class is coupled with the error_handle module ( excepton_generator ).

            Constructors    :
                (KW_ONLY)
                ActiveConnectionLedger( listener : socket ) <- used to produce a ConnectionMultiplexor

            Fields          :

                manager         : ConnectionMultiplexor     <- ( See ConnectionMultiplexor class documentation
                                                            in this module. )
                database        : UserIndex                 <- ( See UserIndex class documentation in this module. )   
        
    '''
    manager     : ConnectionMultiplexor
    database    : UserIndex
    def __init__( self, * , listener : socket ) -> None :
        ''' 
            Constructor
            ( See ActiveConnectionLedger class overview documentation in this module. )

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.manager     = ConnectionMultiplexor(listen_socket=listener)
            self.database    =  UserIndex()
        except Exception as e :
            raise Exception(exception_generator(e))

    def add( self, * , connection : Connection ) -> None : 
        ''' 
        Adds a new connection to the manager dataset and database dataset.

        This function is coupled with the socket module.
        This function is coupled with the database_lib module.
        This function is coupled with the error_handle module ( exception_generator ).
                
                Parameters (KW_ONLY) :
                
                    connection : Connection <- ( See the Connection class documentation in this module 

                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.manager.fd_set.append( connection.csocket )
            self.database.user_set[ connection.csocket ] = connection.client
            self.database.user_count += 1
        except Exception as e :
            raise Exception(exception_generator(e))

    def remove( self , * , connection : socket ) -> None :
        ''' 
        Erases a connection from the manager dataset and database dataset. 
        (Not the primary server database)

        This function is coupled with the error_handle module ( exception_generator ).

                Parameters (KW_ONLY) :
                    
                    connection : socket <- the socket corresponding to the connection to erase

                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            del self.database.user_set[connection]
            self.manager.fd_set.remove(connection)
            self.database.user_count -= 1 
        except Exception as e :
            raise Exception(exception_generator(e))

    def update_key( self, * , connection : socket , key : rsa.RSAPublicKey ) -> None :
        ''' 
        Updates the public key tied to a particular connection in the object database.

        This function is coupled with the cryptography module.
        This function is coupled with the socket module.
        This function is coupled with the error_handle module ( exception_generator ).
                
                Parameters (KW_ONLY) :

                    connection  : socket        <- the socket corresponding to the connection to update
                    key         : RSAPublicKey  <- key to store at specified location

                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.database.user_set[connection].public_key = key
        except Exception as e:
            raise Exception(exception_generator(e))


    def purge(self) -> None :
        ''' 
        Removes all active connections from the object database.

        This function is coupled with the error_handle module ( exception_generator ).
                
                Parameters :
                    None

                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            for _socket in self.manager.fd_set:
                if _socket == sys.stdin or _socket == self.manager.listen_socket:
                    continue
                self.remove(connection=_socket)
        except Exception as e :
            raise Exception(exception_generator(e))

# [ METHOD ]
def srv_welcome_client( * , client : Connection ) -> None :
    ''' 
        Provides newly connected clients with a server welcome message.

        This function is coupled with the socket module.
        This function is coupled with the net_comms_lib module ( transmit ).
        This function is coupled with the error_handle module ( exception_generator ).
                
                Parameters (KW_ONLY) :
                    
                    client : Connection <- ( See Connection class documentation in this module. )

                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        welcome_msg = f'Welcome {client.client.alias}\n{SERVER_GREETING}'
        transmit( msg=welcome_msg , outbound_socket=client.csocket )
    except Exception as e :
        raise Exception(exception_generator(e))

def srv_get_credentials( * , client : Connection ) -> Credentials :
    ''' 
        Retreives credentials from client through a network socket connection.

        ** BLOCKING FUNCTION DEPENDENT ON AN EXTERNAL FACTOR

        This function is coupled with the Connection class ( ** local class ** ).
        This function is coupled with the net_comms_lib module ( receive , utf8decoder ).
        This function is coupled with the net_sec_lib module ( hashed_passwd , Credentials ).
        This function is coupled with the error_handle module ( exception_generator ).
                
                Parameters (KW_ONLY) :
                    
                    client  <- Connection  <- contains information used to reach client

                Returns :
                    Credentials <- ( See Credentials class documentation in net_sec_lib module. )

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        # [ Retrieve username from client ]
        username = receive( inbound_socket=client.csocket , decode_proc=utf8decoder )
        # [ Retrieve password from client ]
        password = hashed_passwd( inbound_socket=client.csocket )
        return Credentials( username=username.strip(), password=password, ip_addr=client.client.ip_addr )
    except Exception as e :
        raise Exception('Failed user authentication : potential (time expired)...')


def srv_user_authenticate( * , client : Connection, database : Database ) -> str:
    '''
        Conducts the authentication process with the client.
        Obtains client credentials and checks agaisnt a database.

        This function is coupled with the socket module.
        This function is coupled with the srv_get_credentials function ( ** local function ** ).
        This function is coupled with the database_lib module ( hasUser , create_new_user , authenticate_user ).
        This function is coupled with the Connection class ( ** local class ** ).
        This function is coupled with the error_handle module ( exception_generator ).
        
                Paramaters  (KW_ONLY) :
                    
                    client      : Connection    ( See Connection class documentation is this module. )
                    database    : Database      ( See Database class documetnation in database_lib. )
            
                Returns :
                    
                    str <- username of authenticated client

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        attempts = 5
        while(True):
            attempts -= 1
            creds = srv_get_credentials( client=client )
            if not database.hasUser( username=creds.username ) :
                database.create_new_user( alias=creds.username ) 
            if ( database.authenticate_user( creds=creds ) ) :
                transmit( msg="OK" , outbound_socket=client.csocket )
                client.update_alias( name=creds.username )
                break
            else :
                transmit( msg="FAILURE" , outbound_socket=client.csocket )
            if attempts: continue 
            else : raise Exception(f"[ - ERROR ] Failed user authentication (max attempts)") 
        return creds.username
    except Exception as e :
        raise Exception(exception_generator(e))


def srv_connect_client( * , client : Connection , 
                       connection_ledger : ActiveConnectionLedger,  
                       database : Database) -> None :
    ''' 
        Processes a client connection with a server , given a database , authenticating the user and logging the
        connection upon success.
        
        This function is coupled with the srv_user_authenticate function ( ** local function ** ).
        This function is coupled with the database_lib module (log_connection ). 
        This function is coupled with the ActiveConnectionLedger add function ( ** local class - local function ** ).
        This function is coupled with the error_handle module ( exception_generator ).

                Parameters (KW_ONLY)    :
                    
                    client              : Connection                <- ( See Connection documentation in this module. )
                    connection_ledger   : ActiveConnectionLedger    <- ( See ActiveConnectionLedger documentation 
                                                                     in this module.)
                    database            : Database                  <- ( See Database documentation in database_lib module. )
                
                Returns :
                    None

                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try: 
        username = srv_user_authenticate( client=client, database=database )
        database.log_connection( alias=client.client.alias , ip_addr=client.client.ip_addr )
        connection_ledger.add( connection=client )
    except Exception as e :
        raise Exception(exception_generator(e))

def srv_accept_client( * , connection_socket : socket ) -> Connection :
    ''' 
        Accepts a network socket connection and creates a client object with the associated
        metadata.

        This function is coupled with the socket module.
        This function is coupled with the Connection class ( ** local class ** ).
        This function is coupled with the error_handle module ( exception_generator ).

                Parameters (KW_ONLY) :

                    connection_socket   : socket    <- the network socket where a connection is 
                                                        to be established

                Returns :

                    Connection  <- metadata associated with accepted client
                
                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        client_socket, client_addr = connection_socket.accept()
        client = Connection(csocket=client_socket,ip_addr=client_addr)
        return client
    except Exception as e :
        raise Exception(exception_generator(e))

def generate_logger( * , logger : Log ) -> Callable[ [str] , None ] :
    ''' 
    

        Given a logging function , returns a decorated server instance of the function.
        Prints a log function message while simultaneously carrying out its default function.


        This function is coupled with the error_handle module ( exception_generator ).

                Parameters (KW_ONLY) :
                    
                    logger  : Log   <- the log function to be decorated

                Returns :
                    
                    Callable[ [str] , None ] <- a log function
                      
                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        def log( message : str ) -> None :
            logger.logging( message )
            print( message )
        return log
    except Exception as e :
        raise Exception(exception_generator(e))

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Abhishek CSEPracticals", "Lewis Van Winkle","ArjanCodes"]
