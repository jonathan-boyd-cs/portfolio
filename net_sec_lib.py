#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    Module <- NET_SEC_LIB

    Author      : Jonathan Boyd
    Context     : Network Programming : SECURE COMMUNICATION

    Provides classes and functions to carry out secure network socket communication functionality.
    Utilizes RSA asymmetric encryption and hashing.

    Project Inception:   09/08/2024

    Mentions    : Errors are accompanied by exceptions specifying the source trail if caught.

    Classes     :
        
        Credentials
        SecureKeyChain
        KeyRing
        Station

    Functions   :

        generate_passwd_hash( * , password : str )
        keys( alias : str )
        key_rsaToString( key : rsa.RSAPublicKey )
        key_stringToRSA( key : str )
        share_key( * , public_key : rsa.RSAPublicKey , outbound_socket : socket )
        retrieve_key( inbound_socket : socket )
        encrypt_rsa( * , message : str , pub_key : rsa.RSAPublicKey )
        decrypt_rsa( * , message : bytes , priv_key : rsa.RSAPrivateKey )
        secure_transmit( * , message : bytes, outbound_socket : socket)
        secure_send( * , message : str , pub_key : rsa.RSAPublicKey , outbound_socket : socket)
        secure_receive( * , inbound_socket : socket , priv_key : rsa.RSAPrivateKey )
        secure_broadcast( * , message : str , sender : str , group : list[SecureKeyChain] )
        hashed_passwd( inbound_socket : socket )        

    Dependencies :

        Custom modules ...
            error_handle
            net_comms_lib

        Well-known modules ...
            crpytography
            dataclasses
            hashlib
            socket

'''
# [ IMPORT ]
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass, field
from error_handle import exception_generator
from hashlib import sha256
from net_comms_lib import receive, send ,transmit
from net_comms_lib import broadcast , utf8decoder 
from net_comms_lib import base64decoder , Message
from net_comms_lib import message_encode , base64encoder
import socket

# [ METHOD ]
def generate_passwd_hash( * , password : str ) -> str :
    ''' 
        Provides a sha256 hashed version of a given password.

        This function is coupled with the hashlib module.

            Parameters (KW_ONLY) :
    
                password : str  <- the password string to be hashed.
    
            Returns     :
                
                str             <- the hashed password

            Exceptions  :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        return sha256(bytes(password)).hexdigest()
    except Exception as e :
        raise Exception(exception_generator(e))

# [ CLASS ]
@dataclass( kw_only=True )
class Credentials:
    '''
        Represents an entity via username , password , and ip address.
        This function dynamically generates a hashed version of the provided
        password.

        This class is coupled with the dataclass module.
        This class is coupled with the generate_passwd_hash function ( **local function** )

            Constructors    :
                
                ( ** KW_ONLY )
                Credentials( username : str , password : str , ip_addr : str )
                    ** Password is not displayed in print.

            Fields          :

                username : str  <- the associated user alias
                password : str  <- the user's password
                ip_addr  : str  <- the user's ip address
            
            Exceptions      :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    username    : str
    password    : str = field( default_factory=generate_passwd_hash , repr=False )
    ip_addr     : str

@dataclass( kw_only=True , frozen=True )
class SecureKeyChain:
    ''' 
        Stores the public key and network socket associated with a user ( alias ).

        This class is coupled with the dataclass module.
        This class is coupled with the cryptography module.

            Constructors    :
                ( ** KW_ONLY ) ( ** FINAL - OBJECT CANNOT BE MODIFIED AFTER INSTANTIATION )
                
                SecureKeyChain( alias : str , public_key : RSAPublicKey , address : socket )

            Fields          :

                alias           : str           <- name associated with the key chain
                public_key      : RSAPublicKey  <- public key associated with the alias
                address         : socket        <- the network socket associated with the alias

            Exceptions      :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    alias       : str
    public_key  : rsa.RSAPublicKey
    address     : socket


@dataclass( kw_only=True, frozen=True , repr=False)
class KeyRing :
    ''' 
            Stores a private key and public key tied to a specified alias.
            This class has no printed representation.

            This class is coupled with the cryptography module.

                Constructors    :
                    ( ** KW_ONLY ) ( ** FINAL - OBJECT CANNOT BE MODIFIED AFTER INSTANTIATION )
                    
                    KeyRing( alias : str , private_key : RSAPrivateKey , public_key : RSAPublicKey )

                Fields          :

                    alias       : str               <- name associated with the key ring
                    private_key : RSAPrivateKey     <- private key associated with the alias
                    public_key  : RSAPublicKey      <- public key associated with the alias


                Exceptions :
       
                    Raises an exception upon miscellaneous error with corresponding trail.
    '''
    alias           : str
    private_key     : rsa.RSAPrivateKey 
    public_key      : rsa.RSAPublicKey


# [ METHOD ]
def keys( alias : str ) -> KeyRing :
    '''
        Generates a public and private key pair.
        
        This function is coupled with the cryptography module.
        This function is coupled with the KeyRing class ( **local class ** )

            Parameters :

                alias : str     <- name to be associated with the key pair

            Returns     :

                KeyRing         <- ( See KeyRing documentation in this module. )

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
        )
        public_key = private_key.public_key()
        return KeyRing( alias=alias,
                        private_key=private_key,
                        public_key=public_key)
    except Exception as e:
        raise Exception(exception_generator(e))

# [ CLASS ]
class Station : 
    ''' 
        Represents a host system which posesses an alias , ip address and public / private
        key pair.
        Represents a member of a public - private key pair network.

        This class is coupled with the KeyRing class ( ** local class ** ).
        This class is coupled with the keys function ( ** local function ** ).
        This class is coupled with the error_handle module ( exception_generator )

            Constructors :
                (KW_ONLY)
                Station( alias : str, ip_addr : str )
                    <- Dynamically generates public - private pair with keys function.

            Fields      :
                keys    : KeyRing       <- ( See KeyRing documentation in this module )
                alias   : str           <- name prescribed to the station
                ip_addr : str           <- ip address associated with station
                

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    keys        : KeyRing
    def __init__( self , *  , alias : str , ip_addr : str ) -> None :
        try:
            self.alias = alias
            self.ip_addr = ip_addr
            self.keys = keys(alias)
        except Exception as e:
            raise Exception(exception_generator(e))


# [ METHOD ]
def key_rsaToString( key : rsa.RSAPublicKey ) -> str:
    ''' 
        Converts an RSAPublicKey to a serialized string.

        This function is coupled with the cryptography module.
        This function is coupled with the error_handle module ( exception_generator )

            Paramters   :
                
                key : RSAPublicKey  <- the key to convert

            Returns     :

                str                 <- the result of conversion

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        _key =str(pem.decode('utf-8'))
        return _key
    except Exception as e:
        raise Exception(exception_generator(e))

def key_stringToRSA( key : str ) -> rsa.RSAPublicKey :
    ''' 
        Converts a string representation of an RSAPublicKey into the RSAPublicKey object.

        This function is coupled with the cryptography module.
        This function is coupled with the error_handle module ( exception_generator ).

            Parameters  : 

                key   : str <- key to convert

            
            Returns     :

                RSAPublicKey    <- result of conversion

            Exceptions  :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        public_key = serialization.load_pem_public_key(
             key.encode('utf-8'),
                backend=default_backend()
        )
        return public_key 
    except Exception as e:
        raise Exception(exception_generator(e))


def share_key( * , public_key : rsa.RSAPublicKey , outbound_socket : socket ) -> None :
    ''' 
        Sends a public key to through a provided network socket.
        Shares a public key with a specified recipient.

        This function is coupled with the cryptography module.
        This function is coupled with the socket module.
        This function is coupled wih the net_comms_lib module ( transmit ).
        This function is coupled with the key_rsaToString function ( ** local function ** )
        This funciton is coupled with the error_handle module

            Parameters (KW_ONLY)    :
                
                public_key      : RSAPublicKey  <- the public key to send
                outbound_socket : socket        <- the network socket through which to send
                                                    the public key
            Returns     :
                None

            Exceptions  :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        public_key_str = key_rsaToString( public_key )
        transmit( msg=public_key_str , outbound_socket=outbound_socket )
    except Exception as e:
        raise Exception(exception_generator(e))


def retrieve_key( inbound_socket : socket ) -> rsa.RSAPublicKey :
    ''' 
        Receives a shared public key from a specified network socket.

        This function is coupled with the cryptography module.
        This function is coupled with the socket module.
        This function is coupled with the net_comms_lib module ( receive , utf8decoder).
        
        ** BLOCKING FUNCTION IS DEPENDENT ON AN EXTERNAL FACTOR ( receive ) 

            Parameters  :

                inbound_socket  : socket    <- where key shall be received

            Exceptions  :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        pub_key_str = receive( inbound_socket=inbound_socket , decode_proc=utf8decoder )
        pub_key_rsa = key_stringToRSA( pub_key_str )
        return pub_key_rsa
    except Exception as e:
        raise Exception(exception_generator(e))


def encrypt_rsa( * , message : str , pub_key : rsa.RSAPublicKey ) -> bytes :
    ''' 
        Encrypts data , or a message , via an rsa public key.

        This function is coupled with the cryptography module.
        This function is coupled with the error_handle module.

            Parameters (KW_ONLY)    :
                
                message : str           <- the data to be encrypted
                pub_key : RSAPublicKey  <- the public key used for encryption

            Returns     :
                
                bytes   <- result of encryption

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        msg = bytes( message , encoding='utf-8' )
        msg_encrypted = pub_key.encrypt(
            msg,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        
        )
        return msg_encrypted
    except Exception as e :
        raise Exception(exception_generator(e))


def decrypt_rsa( * , message : bytes , priv_key : rsa.RSAPrivateKey ) -> bytes :
    '''
        Decrypts bytes via an rsa private key.

        This function is coupled with the cryptography module.
        This function is coupled with the error_handle module ( exception_generator )


            Parameters (KW_ONLY)    :

                message     : bytes         <- data to be decrypted
                priv_key    : RSAPrivateKey <- private key to be used for decryption

            Returns     :
                
                bytes               <- result of decryption

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        msg_decrypted = priv_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return  msg_decrypted 
    except Exception as e :
        raise Exception(exception_generator(e))


def secure_transmit( * , message : bytes, outbound_socket : socket) -> None:
    '''
        Sends data , or a message , through a specified network socket.
        Sends data encoded in base64.

        This function is coupled with the socket module.
        This function is coupled with the net_comms_lib module ( message_encode , base64encoder , send )
        This function is coupled with the error_handle module ( exception_generator ).

            Parameters (KW_ONLY)    :
                
                message         : bytes     <- the data to be transmitted (encrypted data)
                outbound_socket : socket    <- the network socket through which data should be transmitted

            Returns     :
                None

            Exceptions  :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        data = message_encode( msg=message , encoder=base64encoder )
        send( data=data , outbound_socket=outbound_socket )
    except Exception as e :
        raise Exception(exception_generator(e))


def secure_send( * , message : str , pub_key : rsa.RSAPublicKey , outbound_socket : socket) -> None :
    ''' 
        Transmits data , or a message , encrypted with a provided public key. 

        This function is coupled with the socket module.
        This function is coupled with the encrypt_rsa function ( ** local function ** ).
        This function is coupled with the secure_transmit function ( ** local function ** ).
        This message is coupled with the cryptography module.
        This function is coupled with the error_handle module ( exception_generator ).

            Parameters (KW_ONLY) :

                message         : str           <- the data to be transmitted
                pub_key         : RSAPublicKey  <- the public key to be used for encryption
                outbound_socket : socket        <- the network socket through which the data is
                                                    transmitted

            Returns     :
                None

            Exceptions  :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        msg_encrypted = encrypt_rsa( message=message , pub_key=pub_key )
        secure_transmit( message=msg_encrypted , outbound_socket=outbound_socket )
    except Exception as e:
        #print('failed')
        raise Exception(exception_generator(e))


def secure_receive( * , inbound_socket : socket , priv_key : rsa.RSAPrivateKey ) -> str | None :
    '''
        Receives data from a specified network socket and decrypts using provided private key.

        This function is coupled with the socket module.
        This function is coupled with the net_comms_lib module ( receive , base64decoder ).
        This function is coupled with the decrypt_rsa function ( ** local function ** ).
        This function is coupled with the error_handle module ( exception_generator ).

        ** BLOCKING FUNCTION IS DEPENDENT ON AN EXTERNAL FACTOR ( receive ) 

            Parameters (KW_ONLY)    :
                
                inbound_socket  : socket        <- the network socket where data is to be recieved
                priv_key        : RSAPrivateKey <- the private key to be used in data decryption

            Returns         :
                
                str | None          <- data received if available

            Exceptions      :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        msg = receive( inbound_socket=inbound_socket , decode_proc=base64decoder )
        if not msg: return None
        message_decrypted = decrypt_rsa( message=msg , priv_key=priv_key )
        return (message_decrypted.decode('utf-8'))
    except Exception as e:
        print(e)
        raise Exception(exception_generator(e))


def secure_broadcast( * , message : str , sender : str , group : list[SecureKeyChain] ) -> None :
    ''' 
        Sends data , or a message , to a specified group of recipients.
        Utilizes public key cryptography to securely transmit data over
        network sockets.

        This function is coupled with the socket module.
        This function is coupled with the secure_send function ( ** local_function ** ).
        This function is coupled with the SecureKeyChain class ( ** local class ** ).
        This function is coupled with the error_handle module ( exception_generator ).

            Parameters (KW_ONLY) :
                
                message : str                   <- data to be broadcasted
                sender  : str                   <- source of data to be broadcasted
                group   : list[SecureKeyChain]  <- list of recipients with required data
                                                    ( See SecureKeyChain documentation in
                                                        this module. )
            
            Returns             :
                None

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        message = f'{sender}: ' + message
        for entity in group:
            secure_send ( message=message , pub_key=entity.public_key , outbound_socket=entity.address )
    except Exception as e:
        raise Exception(exception_generator(e))


def hashed_passwd( inbound_socket : socket ) -> str | None :
    ''' 
        Retrieves a password from a network socket and returns its hash (sha256).

        This function is coupled with th socket module.
        This function is coupled with the net_comms_lib module ( receive , utf8decoder ).
        This function is coupled with the hashlib module ( sha256 ).

        ** BLOCKING FUNCTION IS DEPENDENT ON AN EXTERNAL FACTOR ( receive ) 

            Parameters  :
            
                inbound_socket  : socket    <- the socket expected to provide the password
    
            Returns     :
                
                str | None                  <- the password hashed or nothing if no reception

            Exceptions :
       
                Raises an exception upon miscellaneous error with corresponding trail.
    '''
    try:
        data = receive( inbound_socket=inbound_socket , decode_proc=utf8decoder )
        if not data: return None
        data = data.encode('utf-8')
        data = sha256( data  ).hexdigest()

        return data
    except Exception as e:
        raise Exception(exception_generator(e))

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Abhishek CSEPracticals", "Lewis Van Winkle","ArjanCodes"]
