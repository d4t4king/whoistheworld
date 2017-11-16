#!/usr/bin/env python
# -*- coding: utf-8 -*-

# sqliteUtils
#

import sqlite3

__version__ = '0.1'

# Useful methods for interacting with sqlite databases
class sqliteUtils(object):
    
    ###################################
    ### Constructor
    def __init__(self, dbfile):
        """
            Return a sqliteUtils object with the dbfile
            we'll be interacting with.
        """
        self.dbfile = dbfile

    ###################################
    def exec_non_query(self, sql):
        """
            Execute a sql commnand with no results.
            Typicall used for INSERT's, UPDATE's, CREATE's, etc.
        """
        conn = sqlite3.connect(self.dbfile)
        with conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            conn.commit()

    ###################################
    def exec_atomic_int_query(self, sql):
        """
            Execute a query that only returns a single integer.
        """
        conn = sqlite3.connect(self.dbfile)
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute(sql)
            except ValueError, err:
                return -1
            conn.commit()
            result = cursor.fetchone()
            my_int = 0
            if 'tuple' in str(type(result)):
                my_int = result[0]
            elif 'int' in str(type(result)):
                my_int = result
            elif 'NoneType' in str(type(result)):
                my_int = False
            else:
                raise TypeError("Unexpected SQL query result tye: {0}.".format(type(result)))
            return my_int

    def exec_single_row_query(self, sql):
        conn = sqlite3.connect(self.dbfile)
        with conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            result = cursor.fetchone()
        return result

    def exec_multi_row_query(self, sql):
        conn = sqlite3.connect(self.dbfile)
        with conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            results = cursor.fetchall()
        return results
