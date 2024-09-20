#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    Module <- NET_COMMS_LIB

    Author: Jonathan Boyd
    Context: Network Programming : Communications

    Provides network socket transmission and reception functionality.

    Project Inception: 09/08/2024

    Mentions: Errors are accompanied by exceptions specifying the source trail if caught.

    Classes         :   
                        Message

    Functions       :
                        
                        utf8decoder( data : bytes )
                        base64decoder( data : bytes )
                        utf8encoder( data : str )
                        base64encoder( data : bytes | str )
                        message_encode( msg : str , encoder : Callable[ [str | bytes] , bytes ])
                        send(data : Message , outbound_socket : socket )
                        transmit( * , msg : str, outbound_socket : socket)
                        receive( * , inbound_socket : socket , decode_proc : Callable[ [bytes], str | bytes ])
                        broadcast( * , msg : str, sender : str, group : list[socket])


    CONSTANTS       :
                        C_FORMAT        = 'utf-8'   <- encoding format for transmission and reception
                        HEADER_SIZE     = 64        <- size of header messages sent to detail incoming transmission sizes


    Dependencies    :

        Custom modules ...
            error_handle

        Well-known modules ...
            base64
            dataclasses
            socket
'''
# [ IMPORT ]
import base64
from collections.abc import Callable
from dataclasses import dataclass
from error_handle import exception_generator
import socket

# [ CONSTANT ]
C_FORMAT = 'utf-8'
HEADER_SIZE = 64

# [ CLASS ]
@dataclass( kw_only=True , frozen=True )
class Message :
    ''' 
        Represents content to be transmitted over a connection socket and that content's size ( in bytes )

            Constructor ( KW_ONLY ) ( FINAL - OBJECT CANNOT BE MODIFIED AFTER INSTANTIATION ):
                
                Message( content : bytes , size : bytes )
                    

            Fields :
                
                content     : bytes     <- encoded data to be transmitted
                size        : bytes     <- encoded representation of size of content
    '''
    content     : bytes
    size        : bytes


# [ METHOD ]
def utf8decoder( data : bytes ) -> str :
    ''' 
        Converts (decoding) bytes via utf-8 format specifier.
        This function is coupled with the error_handle module ( exception_generator )

            Parameters  :

                data : str  <- bytes to be converted

            Returns     :

                str         <- decoded data

            Exception   :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        return data.decode('utf-8')
    except Exception as e:
        raise Exception(exception_generator(e))

def base64decoder( data : bytes ) -> bytes :
    ''' 
        Converts (decoding) bytes via base64 format specifer.

        This function is coupled with the base64 module ( b64decode ).
        This function is coupled with the error_handle module ( exception_generator )

            Parameters  :
                data : bytes    <- bytes to be converted

            Returns     :
                bytes           <- bytes post decode

            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        return base64.b64decode(data)
    except Exception as e:
        raise Exception(exception_generator(e))

def utf8encoder( data : str ) -> bytes :
    ''' 
        Converts (encoding) a string to bytes via utf-8 format specifier.

        This function is coupled with the error_handle module ( exception_generator )

            Parameters  :
                
                data : str  <- string to be converted

            Returns     :
                
                bytes       <- result of encoding

            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        return data.encode('utf-8')
    except Exception as e:
        raise Exception(exception_generator(e))

def base64encoder( data : bytes | str ) -> bytes :
    ''' 
        Converts (encoding) a string or bytes via base64 format specifier.

        This function is coupled with the error_handle module ( exception_generator )

            Parameters  : 
                
                data : bytes | str  <- data to be converted

            Returns     :

                bytes               <- result of encoding
            
            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        if type( data ) == str:
            data = data.encode('utf-8')
        return base64.b64encode( data )
    except Exception as e:
        raise Exception(exception_generator(e))

def message_encode( * , msg : str , encoder : Callable[ [str | bytes] , bytes ]) -> Message:
    ''' 
        Converts a string of data , or message , via a desired encoding format , into bytes

        This function is coupled with the collections.abc module ( Callable ).
        This function is coupled with the local encoder functions ( utf8encoder , b64encoder ).
        This function is coupled with the error_handle module ( exception_generator )


            Parameters (KW_ONLY) :

                msg     : str                           <- the data to be encoded
                encoder : Callable[[str|bytes],bytes]   <- encoding function characterized by
                                                        str or bytes parameter , returns bytes
            Returns :
                
                Message     <- ( See Message documentation in this module. )

            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        encoded_msg = encoder( msg )
        msg_length = str( len( encoded_msg ) )
        msg_length = encoder( msg_length )
        msg_length += b' ' * ( HEADER_SIZE - len( msg_length ) )
        return Message( content=encoded_msg, size=msg_length )
    except Exception as e :
        raise Exception(exception_generator(e))

def send( * , data : Message , outbound_socket : socket ) -> None:
    ''' 
        Sends data through a socket.

        This function is coupled with the socket module.
        This function is coupled with the Message class ( **local class** )
        This function is coupled with the error_handle module ( exception_generator )

            Parameters (KW_ONLY) :
                
                data            : Message   <- ( See Message documentation in this module. )
                outbound_socket : socket    <- the socket through which information is sent

            Returns     :
                None

            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        outbound_socket.send( data.size )
        outbound_socket.send( data.content )
    except Exception as e :
        raise Exception(exception_generator(e))

def transmit( * , msg : str, outbound_socket : socket) -> None:
    '''
        Encodes message data represented as a string and sends it out a network socket.

        This function is coupled with message_encode ( **local function** )
        This function is coupled with send ( **local function )
        This function is coupled with the error_handle module ( exception_generator )
            
            Parameters (KW_ONLY) :
                
                msg             : str       <- data to be encoded and sent
                outbound_socket : socket    <- socket out of which data is sent

            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        data = message_encode( msg=msg , encoder=utf8encoder )
        send( data=data , outbound_socket=outbound_socket )
    except Exception as e :
        raise Exception(exception_generator(e))


def receive( * , inbound_socket : socket , decode_proc : Callable[ [bytes], str | bytes ]) -> str | bytes | None :
    ''' 
        Retrieves an inbound message from a network socket.

        
        ** BLOCKING FUNCTION DEPENDING ON AN EXTERNAL FACTOR (receive) **
        
        This function is coupled with the socket module.
        This function is coupled with the local decoder functions ( utf8decoder , base64decoder )
        This function is coupled with the error_handle module ( exception_generator )

            Parameters (KW_ONLY):

                inbound_socket      : socket                        <- the socket from which a message 
                                                                        is to be received
                
                decode_proc         : Callable[[bytes],str|bytes]   <- the decoder corresponding to anticipated
                                                                        data encoding format

            Returns     :
                str | byte | None   <- data retreived if retreived
            
            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        msg_length = inbound_socket.recv(HEADER_SIZE)
        if not msg_length:
            return None
        
        msg_length = decode_proc( msg_length )
        msg = inbound_socket.recv(int(msg_length))
        msg = decode_proc( msg )

        return msg
    except Exception as e :
        raise Exception(exception_generator(e))

def broadcast( * , msg : str, sender : str, group : list[socket]) -> None :
    ''' 
        Sends provided message to a group of recipients.
        Transmits data out of multiple sockets.
        Prepends data with sender's name.

        This function is coupled with the socket module.
        This function is coupled with the message_encode function ( **local function** )
        This function is coupled with the send function ( **local function** )
        This function is coupled with the error_handle module ( exception_generator )
        
            Parameters (KW_ONLY) :
                
                msg         : str           <- message to be broadcasted
                sender      : str           <- source of the message to be broadcasted
                group       : list[socket]  <- list of sockets to transmit message out of

            Returns     :
                None

            Exceptions  :

                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try :
        msg = f'{sender} : {msg}'
        data = message_encode( msg=msg , encoder=utf8encoder )
        print(f'[ ALERT ] BROADCAST {sender} broadcasting: {msg}.')
        for outbound_socket in group:
            send( data=data , outbound_socket=outbound_socket )
    except Exception as e :
        raise Exception(exception_generator(e))

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Abhishek CSEPracticals", "Lewis Van Winkle","ArjanCodes"]
