#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    Module <- CLIENT_LIB

    Author: Jonathan Boyd
    Context: Network Programming : Client Server ( Client - Side )

    Provides client authentication , server connection , and input functionality

    Project Inception: 09/08/2024

    Mentions: Errors are accompanied by exceptions specifying the source trail if caught.

    Functions :

            user_input( prompt : str , timeout : int )
            get_credentials()
            authenticate_user( credentials : Credentials , server_socket : socket )
            login( SERVER : tuple[ ip_addr : str , port : int ] )

    Dependencies :

        Custom modules ...
            error_handle
            net_comms_lib
            net_sec_lib

        Well-known modules ...
            select
            socket
            sys
'''
# [ IMPORT ]
from error_handle import exception_generator
from net_comms_lib import transmit, receive, utf8decoder
from net_sec_lib import Credentials
import select
import socket
import sys

# [ METHOD ]
#https://stackoverflow.com/questions/15528939/time-limited-input
def user_input( * , prompt : str , timeout : int ) -> str :
    ''' 
        Retrieves user input with the additional of a limited time window.
        The function strips inputs of leading and trailing spaces.
        The function is coupled with the select module ( enforcing time ).
        This function is coupled with the sys module (reading input ).
        This function is coupled with the error_handle module ( exception_generator )

            Parameters (KW_ONLY) :
            
                prompt  : str       <- Displays a message conveying the context of the input.
                timeout : int       <- Enforces a time limit on user responses.

            Returns :
                
                str                 <- users response

            Exceptions :
                
                Raises an exception upon time expired.
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try :
        while(True):
            sys.stdout.write(prompt)
            sys.stdout.flush()
            read, _, _ = select.select([sys.stdin], [], [], timeout)
            if read :
                inpt = sys.stdin.readline().rstrip('\n')
                if inpt == '': continue
                else: return inpt
            raise Exception("TimeoutExpired")
    except Exception as e :
        raise Exception(exception_generator(e))

def get_credentials() -> Credentials :
    ''' 
        Retrieves the username and password of the user.
       


        This function is coupled with the net_sec_lib module ( see class:Credentials ).
        This function is coupled with the user_input function ( **local fucntion** ).
        This function is coupled with the error_handle module ( exception_generator )

            Parameters :
                None

        Returns:
            Credentials <- see net_sec_lib#Credentials

        Exceptions :

            Raises an exception upon failure to retrieve either username or password.
            Raises an exception upon miscellaneou error with corresponding trail.
    '''
    try:
        username = user_input( prompt="Username: ", timeout=8 )
        password = user_input( prompt="Password: ", timeout=8 )
        return Credentials( username=username , password=password , ip_addr='' )
    except Exception as e: 
        raise Exception(exception_generator(e))

def authenticate_user( * , credentials : Credentials, server_socket : socket ) -> bool :
    ''' 
        Validates user credentials with a server.
        Sends credentials to a server and receives a response.

        This function is coupled with the net_comms_lib ( function:transmit , function:receive )
        This function is coupled with the error_handle module ( exception_generator )
        
        ** BLOCKING FUNCTION DEPENDING ON AN EXTERNAL FACTOR (receive) **

            Parameters (KW_ONLY) :  

                credentials     : Credentials   <- Contains the user's username and password.
                server_socket   : socket        <- The network socket actively connected with a server.

            Returns :
            
                bool                            <- Success or failure in authentication

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.

    '''
    try:
        # [ sending username to server ]
        transmit( msg=credentials.username , outbound_socket=server_socket )
        # [ sending password to server ]
        transmit( msg=credentials.password , outbound_socket=server_socket )
        # [ listening for server validation response ]
        server_response = receive( inbound_socket=server_socket , decode_proc=utf8decoder )
        if server_response == 'OK':
            return False
        else:
            return True
    except Exception as e:
        raise Exception(exception_generator(e))

def login( * , SERVER : tuple[str,int] , max_attempts : int ) -> socket :
    ''' 
        Attempts to establish a connection with a remote server.
        Creates a socket connected to a server and authenticates user.

        ** BLOCKING FUNCTION DEPENDING ON AN EXTERNAL FACTOR (receive) **
        
        This function is coupled with the socket module.
        This functin is coupled with the net_comms_lib module ( function:receive ).
        This function is coupled with the get_credentials function ( **local function** ).
        This function is coupled with the authenticate_user function ( **local function** ).
        This function is coupled with the error_handle module ( exception_generator )

            Parameters (KW_ONLY) :
            
                SERVER          : tuple[str , int]      <-  tuple[ ip_addr , port ] <- used for socket creation
                max_attempts    : int                   <-  Provides a bound for number
                                                            of allowed incorrect passwords.

            Returns :
            
                socket                                  <-  the established socket with a server

            Exceptions :

                Raises an exception and closes a potentially open socket upon unexpected error.  
                Raises an exception upon miscellaneous error with corresponding trail.
    
    '''
    try:
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_socket.connect(SERVER)
        attempts = 0
        while ( attempts < max_attempts ) :
            credentials = get_credentials()
            if not authenticate_user( credentials=credentials , server_socket=local_socket ) :
                # [ receive server welcome ]
                print( receive( inbound_socket=local_socket , decode_proc=utf8decoder ) )
                return local_socket
            attempts += 1
            print(f'attempt: {attempts}')
        raise Exception("Login failure: attempts exceeded")
    except  Exception as e:
        if local_socket:
            local_socket.close()

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Abhishek CSEPracticals", "Lewis Van Winkle","ArjanCodes"]
