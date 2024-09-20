#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    Module <- DATABASE_LIB

    Author: Jonathan Boyd
    Context: Network Programming : Client Server ( DATABASE )

    Provides database with statistics functionality

    Project Inception: 09/08/2024

    Mentions: Errors are accompanied by exceptions specifying the source trail if caught.

    Classes :
        
        Database

    Functions :
        
        create_new_user( alias : str )
        authenticate_user( creds : Credentials )
        log_connection( alias : str , ip_addr : str )
        purge( self , * , users : list[str])
        update_stats( self , * , username : str, stats : list[tuple[str,int]] )
        hasUser( self, * , username : str )
        audit()
        save()


    Dependencies :

        Custom modules ...
            error_handle
            net_sec_lib

        Well-known modules ...
            dataclasses
            json
'''

from dataclasses import dataclass, field
from error_handle import exception_generator
import json
from net_sec_lib import Credentials

class Database:
    ''' 
        Servers as a client database for any server client implementation.
        
        This class allows for simple expansion of statistics.

        This class is coupled with the net_sec_lib module ( class:Credentials ).
        This class is coupled with the error_handle module ( function:exception_generator )
        This class is coupled with the dataclasses module ( [ dataclass , field ] <- dataclasses )

        Fields :
            __user_data_file    <-  File maintains user authentication information and statistics.
                                    The file is generated automatically if it does not exist.
                                    The file stores information in json format.

            __db                <-  The database itself, holding the user data at runtime.


        Constructors :
            
            Database()          <-  Default :   Loads user information from the default
                                                'user_data.json' file if it exists, else
                                                instantiates an empty user database.

            Database( user_data_file : str )
                                <-  One arg :   Loads user information from the provided 
                                                file name. ( JSON formatted per database specs )
                                        * only advised if saving a file renamed after a previous
                                        shutdown sequence. ( Database saves on server shutdown 
                                                            when properly implemented. )

        Methods :
            
            create_new_user( alias : str )
            authenticate_user( creds : Credentials )
            log_connection( alias : str , ip_addr : str )
            purge( self , * , users : list[str])
            update_stats( self , * , username : str, stats : list[tuple[str,int]] )
            hasUser( self, * , username : str )
            display()
            save()
   

        Database Statistics (DICTIONARY) :
                    
                    key:'alias'         : alias : str ,
                    
                    key:'ip_ledger'     :   {
                                            key:'addr_list_ATTEMPT'  : list[str],
                                            key:'addr_list_SUCCESS'  : list[str],
                                            key:'addr_active'        : str
                                            } : dict ,

                    key:'credentials'   :   {
                                            key:'username'          : str, 
                                            key:'password'          : str , 
                                            key:'ip_addr'           : str
                                            } : dict ,
                    
                    key:'statistics'    :   {
                                            key:'active_connections'         : int,
                                            key:'successful_broadcast_count' : int,
                                            key:'logon_count'                : int,
                                            Key:'logoff_count'               : int
                                            } : dict
   '''
    def __init__( self, user_data_file : str = 'user_data.json' ) -> None :
        ''' 
            Loads user information from './user_data.json' if it exists, else
            instantiates an empty user database. ** If a file name is provided 
            the constructor will opt to attempted loading from that file.


            This function is coupled with the error_handle module ( exception_generator )
            
                Parameters :

                    ( OPTIONAL ) user_data_file : str <- file name of user data store
        
                Returns :
                    None

                Exceptions:

                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.__user_data_file = user_data_file
            try:
                with open(user_data_file , 'r') as f :
                    self.__db = json.loads(f.read())
            except:
                self.__db = {'users' :{}}
        except Exception as e:
            raise Exception(exception_generator(e))


    def create_new_user(self, * , alias : str ) -> None :
        ''' 
            Creates a new user and instantiates the corresponding dictionary.
            Produces a dictionary which, denoted by the user alias, will store user
            credentials and statistics.


            This function is coupled with the error_handle module ( exception_generator )

                Parameters (KW_ONLY): 

                    alias : str     <-  the prescribed name of the user

                Returns :
                    None

                Exceptions :
                         
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            self.__db['users'][alias] = {
                    'alias'         : alias,
                    'ip_ledger'     : {'addr_list_ATTEMPT'  : [],
                                       'addr_list_SUCCESS'  : [],
                                       'addr_active'        : ''},
                    'credentials'   : {'username'       : alias , 
                                       'password'       : '' , 
                                       'ip_addr'        : ''},
                    'statistics'    : {'active_connections'         : 0,
                                       'successful_broadcast_count' : 0,
                                       'logon_count'                : 0,
                                       'logoff_count'               : 0}
            }
        except Exception as e :
            raise Exception(exception_generator(e))

    def authenticate_user( self , * , creds : Credentials) -> bool :
        ''' 
            Authenticates a user with the database based on username and password.
            Logs the associated ip address for security auditing.
            
            This method is coupled with the net_sec_lib module ( Credentials )
            This function is coupled with the error_handle module ( exception_generator )


                Parameters (KW_ONLY) :
                
                    creds : Credentials <- Provides the user's ip address , username and password.

                Returns :
                    bool                <- result of authentication ( success or failure )

                Exceptions :

                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            if creds.username not in self.__db['users'] :
                return False
            self.__db['users'][creds.username]['ip_ledger']['addr_list_ATTEMPT'].append(creds.ip_addr)
            if self.__db['users'][creds.username]['statistics']['logon_count'] == 0 :
                self.__db['users'][creds.username]['credentials']['password'] = creds.password
            else :
                if not self.__db['users'][creds.username]['credentials']['password'] == creds.password:
                    return False
            return True
        except Exception as e :
            raise Exception(exception_generator(e))

    def log_connection( self, * , alias : str, ip_addr : str ) -> None :
        ''' 
            Updates the user statistics associated with a user's successful logon and authentication.

            This function is coupled with the error_handle module ( exception_generator )

                Parameters (KW_ONLY) :
                
                    alias : str     <- the name of the user in the database
                    ip_addr : str   <- the ip address that the user is currently connecting from

                Returns :
                    None

                Exceptions :
                
                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        user = alias
        try:
            self.__db['users'][user]['ip_ledger']['addr_list_SUCCESS'].append(ip_addr)
            self.__db['users'][user]['ip_ledger']['addr_active'] = ip_addr
            self.__db['users'][user]['statistics']['active_connections'] += 1
            self.__db['users'][user]['statistics']['logon_count'] += 1 
        except Exception as e :
            raise Exception(exception_generator(e))

    def purge( self , * , users : list[str]) -> None :
        ''' 
            Reflects a user logoff from the database per user specified in
            a provided list.

            This function is coupled with the error_handle module ( exception_generator )

                Parameters (KW_ONLY) :
                
                    users : list[str]   <- list of users to be 'logged off'

                Returns :
                    None

                Exception :

                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            for user in users :
                self.__db['users'][user]['statistics']['active_connections'] -= 1
                self.__db['users'][user]['statistics']['logoff_count'] += 1
                self.__db['users'][user]['ip_ledger']['addr_active'] = '' 
        except Exception as e :
            raise Exception(exception_generator(e))

    def update_stats( self , * , username : str, stats : list[tuple[str,int]] ) -> None :
        ''' 
            Modifies statistics of a specified user.
            Takes a list of database specific statistics and associated increment values.

            This function is coupled with the error_handle module ( exception_generator )

                Parameters (KW_ONLY) :

                    username : str                      <- name of user to be updated
                    stats : list[tuple[str,int]] <- list[ tuple['stat_to_update' , 'increment_value'] ]
             
                Returns :
                    None

                Exceptions :

                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            for (key,value) in stats :
                self.__db['users'][username]['statistics'][key] += value
        except Exception as e :
            raise Exception(exception_generator(e))

    def hasUser( self, * , username : str ) -> bool :
        ''' 
            Checks whether a user exists within the database.

            This function is coupled with the error_handle module ( exception_generator )

                Parameters (KW_ONLY) :

                    username : str  <- the name of the user to query

                Returns :
                    
                    bool            <- result of search ( found or not found )

                Exceptions :

                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            return username in self.__db['users']
        except Exception as e:
            raise Exception(exception_generator(e))

    def audit( self ) -> None :
        ''' 
            Writes an audit of the current database instance to a file named
            database_audit.txt.
            Provides details on all known users and corresponding statistics.
            
            This method APPENDS to the database_audit.txt file.

            This method is coupled with the json module ( dumps )
            This function is coupled with the error_handle module ( exception_generator )


                Parameters :
                    None

                Returns :
                    None

                Excpetions :

                    Raises an exception upon miscellaneous error with corresponding trail. 
        '''
        try:
            with open( 'database_audit.txt' , 'a') as f:
                data = json.dumps(self.__db,indent=1)
                f.write('====\n====\n====\n====\n')
                f.write(data)
                f.write('\n****\n****\n****')
        except Exception as e :
            raise Exception(exception_generator(e))

    def save( self ) -> None :
        ''' 
            Stores the database in a json file ( __user_data_file.json ).
            Maintains all known user credentails and statistics.
        
            This function is coupled with the error_handle module ( exception_generator )

                Parameters :
                    None

                Returns :
                    None

                Exceptions :

                    Raises an exception upon miscellaneous error with corresponding trail.
        '''
        try:
            with open(self.__user_data_file,'w') as f :
                json.dump(self.__db, f)
                
        except Exception as e :
            raise Exception(exception_generator(e))

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Jonathan Boyd", "Abhishek", "Lewis Van Winkle","ArjanCodes"]
__email__ = "jonboyd@uiowa.edu"
