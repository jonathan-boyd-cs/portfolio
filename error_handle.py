#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    Module <- ERROR_HANDLE

    Author: Jonathan Boyd
    Context: Centralized exception handler

    Provides a central location to customize error messages for programming implementation in python.

    Project Inception: 09/08/2024

    Functions       :

            exception_generator( exception : Exception )

    Dependencies    :

        Well-known modules ...
            inspect
'''
#[ IMPORTS ]
import inspect

#[ METHODS ]
def exception_generator( exception : Exception ) -> str :
    ''' 
        Provides a generalized exception message to be raised within any given program.
        Returns the function corresponding to the exception along with the implementation
        specific exception error which was caught.

            Parameters  :

                exception : Exception <- the caught exception

            Returns     :

                str <- a message to be raised

            Exceptions  :
                " HA HA HA ..."
    '''
    return f'\nFailure in {inspect.currentframe().f_back.f_code.co_name}.\n[ err DETAIL ] <- {exception}\n'

#--------------------------------------------------------------------
__author__ = "Jonathan Boyd"
__credits__ = ["Abhishek CSEPracticals", "Lewis Van Winkle","ArjanCodes"]
