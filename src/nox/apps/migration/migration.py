#!/usr/bin/python
"""
migration.py [-hp] [--help ][--plugin directory] <database>

The tool migrates the contents of the database to the latest schema
versions.
"""

# Copyright 2008 (C) Nicira, Inc.

import getopt
import os
import tempfile
import traceback
import shutil
import sqlite3
import sys

class Plugin:
    """
    A plugin migrates a row from a table version to next.  All plugins
    should implement this interface.
    """
    INTEGER, TEXT, DOUBLE, GUID = [ 0, 1, 2, 3 ]

    def get_table(self):
        """
        Return the table name.
        """
        raise NotImplementedError

    def get_version(self):
        """
        Return the version that can be migrated to the next version (+1).
        """
        raise NotImplementedError

    def get_schema(self):
        """
        Return the new schema to use when creating the table.
        """
        raise NotImplementedError

    def migrate(self, row):
        """
        Return the migrated row
        """
        raise NotImplementedError

    def get_new_rows(self):
        """
        Return tuple of new rows that should be added as part of the migration.
        Called after all existing rows have been migrated using migrate()
        """
        return ()

    def is_meta_table(self):
        """
        Return true for plugins updating meta tables.
        """
        return False

class Schema_meta_plugin(Plugin):
    """
    A plugin updating the main meta table from version 0 to 1.
    """
    def get_table(self): return 'NOX_SCHEMA_META'
    def get_version(self): return 0
    def get_schema(self): return \
    [
        {
            'GUID' : self.GUID,
            'NOX_TABLE' : self.TEXT,
            'NOX_TYPE' : self.INTEGER,
            'NOX_VERSION' : self.INTEGER
        },
        {
            'NOX_SCHEMA_META_INDEX_1' : ( 'NOX_TABLE', ),
        }
    ]

    def migrate(self, row):
        row['NOX_VERSION'] = 0
        return row

    def is_meta_table(self):
        return True

def load_plugins(plugin_dirs):
    """
    Scan the directories
    """
    p = {}

    # Built-in plugin to migrate the meta table
    p['NOX_SCHEMA_META'] = [ Schema_meta_plugin() ]

    for plugin_dir in plugin_dirs:
        sys.path.append(plugin_dir)

        for root, dirs, files in os.walk(plugin_dir):
            for file in files:
                if file[-10:].lower() == '_plugin.py' or file[-11:].lower() == '_plugin.pyc':
                    try:
                        if root[:2] == '.':
                            module = file[:-3]
                        else:
                            if root[:2] == './':
                                module = root[2:] + '/' + file[:-3]
                            else:
                                module = root + '/' + file[:-3]

                        m = __import__(module)
                        for plugin in m.get_plugins():
                            if not p.has_key(plugin.get_table()):
                                p[plugin.get_table()] = [ ]
                            p[plugin.get_table()].append(plugin)

                    except AttributeError, e:
                        pass
                    except Exception, e:
                        print "Plugin '%s' failed to import: %s"%(file,e)
                        return None
        sys.path.pop()
    return p

def load_tables_ver_0(database_conn):
    c1 = database_conn.cursor()

    try:
        tables = []
        c1.execute('SELECT * FROM NOX_SCHEMA_META')
        for row in c1:
            if row['NOX_TYPE'] == 0: # PERSISTENT
                table_name = row['NOX_TABLE']
                c2 = database_conn.cursor()
                c2.execute('SELECT * FROM NOX_SCHEMA_TABLE WHERE NOX_TABLE ="%s"' %
                           table_name)
                columns = {}
                for row in c2:
                    columns[row['NOX_COLUMN']] = row['NOX_TYPE']

                c2.execute('SELECT * FROM NOX_SCHEMA_INDEX WHERE NOX_TABLE = "%s"'%
                           table_name)
                indices = {}
                for row in c2:
                    if not indices.has_key(row['NOX_INDEX']):
                        indices[row['NOX_INDEX']] = []
                    indices[row['NOX_INDEX']].append(row['NOX_COLUMN'])
                
                c2.close()
                tables.append((table_name,
                               0, # Initial meta table version #
                               (columns, indices) ))
        c1.close()
        return [ ('NOX_SCHEMA_META', 0, 
               (
                    {
                        'GUID' : Plugin.GUID,
                        'NOX_TABLE' : Plugin.TEXT,
                        'NOX_TYPE' : Plugin.INTEGER,
                        'NOX_VERSION' : Plugin.INTEGER
                        },
                    {
                        'NOX_SCHEMA_META_INDEX_1' : [ 'NOX_TABLE', ]
                        }
                    )
               ),
              ('NOX_SCHEMA_INDEX', 0, 
               (
                    {
                        'GUID' : Plugin.GUID,
                        'NOX_TABLE' : Plugin.TEXT,
                        'NOX_INDEX' : Plugin.TEXT,
                        'NOX_COLUMN' : Plugin.TEXT,
                        },
                    {
                        'NOX_SCHEMA_INDEX_INDEX_1' : [ 'NOX_TABLE', ]
                        }
                    )
               ),
              ('NOX_SCHEMA_TABLE', 0, 
               (
                    {
                        'GUID' : Plugin.GUID,
                        'NOX_TABLE' : Plugin.TEXT,
                        'NOX_COLUMN' : Plugin.TEXT,
                        'NOX_TYPE' : Plugin.INTEGER,
                        },
                    {
                        'NOX_SCHEMA_TABLE_INDEX_1' : [ 'NOX_TABLE', ]
                        }
                    )
               ) 
              ] + tables
    except Exception, e:
        print e
        traceback.print_exc()
        c1.close()
        raise

def load_tables_ver_1(database_conn):
    c1 = database_conn.cursor()

    try:
        tables = []
        c1.execute('SELECT * FROM NOX_SCHEMA_META')
        for row in c1:
            if row['NOX_TYPE'] == 0: # PERSISTENT
                table_name = row['NOX_TABLE']
                table_version = row['NOX_VERSION']

                c2 = database_conn.cursor()
                c2.execute('SELECT * FROM NOX_SCHEMA_TABLE WHERE NOX_TABLE ="%s"' %
                           table_name)
                columns = {}
                for row in c2:
                    columns[row['NOX_COLUMN']] = row['NOX_TYPE']

                c2.execute('SELECT * FROM NOX_SCHEMA_INDEX WHERE NOX_TABLE = "%s"'%
                           table_name)
                indices = {}
                for row in c2:
                    if not indices.has_key(row['NOX_INDEX']):
                        indices[row['NOX_INDEX']] = []
                    indices[row['NOX_INDEX']].append(row['NOX_COLUMN'])
                
                c2.close()
                tables.append((table_name,
                               table_version,
                               (columns, indices) ))
        c1.close()
        return [ ('NOX_SCHEMA_META', 1, 
               (
                    {
                        'GUID' : Plugin.GUID,
                        'NOX_TABLE' : Plugin.TEXT,
                        'NOX_TYPE' : Plugin.INTEGER,
                        'NOX_VERSION' : Plugin.INTEGER
                        },
                    {
                        'NOX_SCHEMA_META_INDEX_1' : [ 'NOX_TABLE', ]
                        }
                    )
               ),
              ('NOX_SCHEMA_INDEX', 0, 
               (
                    {
                        'GUID' : Plugin.GUID,
                        'NOX_TABLE' : Plugin.TEXT,
                        'NOX_INDEX' : Plugin.TEXT,
                        'NOX_COLUMN' : Plugin.TEXT,
                        },
                    {
                        'NOX_SCHEMA_INDEX_INDEX_1' : [ 'NOX_TABLE', ]
                        }
                    )
               ),
              ('NOX_SCHEMA_TABLE', 0, 
               (
                    {
                        'GUID' : Plugin.GUID,
                        'NOX_TABLE' : Plugin.TEXT,
                        'NOX_COLUMN' : Plugin.TEXT,
                        'NOX_TYPE' : Plugin.INTEGER,
                        },
                    {
                        'NOX_SCHEMA_TABLE_INDEX_1' : [ 'NOX_TABLE', ]
                        }
                    )
               ) 
              ] + tables
    except Exception, e:
        print e
        traceback.print_exc()
        c1.close()
        raise

def load_tables(database_conn):
    # Determine the meta table version by trying the newest support
    # version and proceed to older versions one by one.
    f = [ 
        lambda conn: load_tables_ver_1(conn), 
        lambda conn: load_tables_ver_0(conn), 
        ]
    
    while len(f):
        try:
            return f[0](database_conn)
        except Exception, e:
            f = f[1:]

    raise RuntimeError('Unknown meta table format')

def create_table(table_name, table_schema, database_conn):
    c = database_conn.cursor()

    columns, indices = table_schema

    sql = ''
    for column in columns:
        if len(sql) > 0:
            sql += ', '

        sql_type = {
            Plugin.INTEGER: 'INTEGER',
            Plugin.TEXT: 'TEXT',
            Plugin.DOUBLE: 'DOUBLE',
            Plugin.GUID: 'INTEGER',
            }[columns[column]]
        if column == 'GUID':
            sql_type = 'INTEGER PRIMARY KEY'
        sql += column + ' ' + sql_type + ' NOT NULL'

    c.execute('CREATE TABLE ' + table_name + ' (' + sql + ')')

    for index_name in indices:
        index_columns = indices[index_name]
        c.execute('CREATE INDEX ' + index_name + ' ON ' + table_name + \
                      '(' + ', '.join(index_columns) + ')')

    c.close()

def migrate_table(table, plugins, old_database_conn, new_database_conn):
    def _add_row(cursor, table_name, row):
        columns = ', '.join(row.keys())
        vars = ', '.join(map(lambda x: '?', row.keys()))
        sql = 'INSERT INTO ' + table_name + \
            '(' + columns + ') VALUES (' + vars + ')'
        cursor.execute(sql, row.values())

    table_name, table_version, loaded_schema = table

    plugins_to_run = []
    while True:
        try:
            if plugins.has_key(table_name):
                for plugin in plugins[table_name]:
                    if plugin.get_version() == table_version:
                        plugins_to_run.append(plugin)
                        table_version += 1
                        raise RuntimeError
            break
        except:
            pass

    if len(plugins_to_run) == 0:
        print '''No migration plugins found for '%s'. Copying contents as such.''' % table_name

        c1 = old_database_conn.cursor()
        c2 = new_database_conn.cursor()

        create_table(table_name, loaded_schema, new_database_conn)

        c1.execute('SELECT * FROM ' + table_name)
        for row in c1:
            columns = ', '.join(row.keys())
            vars = ', '.join(map(lambda x: '?', row.keys()))
            sql = 'INSERT INTO ' + table_name + \
                '(' + columns + ') VALUES (' + vars + ')'
            c2.execute(sql, row.values())

        c1.close()
        c2.close()
        return 

    for plugin in plugins_to_run:
        print '''Migrating '%s' from version %d to the latest version...''' % \
            (table_name, plugin.get_version())

    c1 = old_database_conn.cursor()
    
    create_table(table_name, plugins_to_run[-1].get_schema(), new_database_conn)
        
    c2 = new_database_conn.cursor()
    c1.execute('SELECT * FROM ' + table_name)
    for row in c1:
        migrated_row = row
        for plugin in plugins_to_run:
            migrated_row = plugin.migrate(migrated_row)
        _add_row(c2, table_name, migrated_row)

    #allow the plugin to add new rows, after it has seen all existing rows
    p2r = plugins_to_run[:]
    for plugin in plugins_to_run:
        p2r.pop(0)
        new_rows = plugin.get_new_rows()
        for row in new_rows:
            migrated_row = row
            for plugin in p2r:
                migrated_row = plugin.migrate(migrated_row)
            _add_row(c2, table_name, migrated_row)

    # Update the meta tables' content to the latest version for every
    # non-meta tables:
    if not plugins_to_run[-1].is_meta_table():
        c2.execute('''UPDATE NOX_SCHEMA_META SET NOX_VERSION = %d WHERE NOX_TABLE = '%s' ''' % 
                   ( table_version, table_name))
        
        c2.execute('''DELETE FROM NOX_SCHEMA_TABLE WHERE NOX_TABLE = '%s' ''' %(table_name))
        c2.execute('''DELETE FROM NOX_SCHEMA_INDEX WHERE NOX_TABLE = '%s' ''' %(table_name))
        
        columns, indices = plugins_to_run[-1].get_schema()
        indices["%s_PRIMARY_GUID_INDEX" % table_name] = ( 'GUID', )
        for column, type in columns.iteritems():
            sql = 'INSERT INTO NOX_SCHEMA_TABLE' + \
                '(NOX_TABLE, NOX_COLUMN, NOX_TYPE) VALUES (?, ?, ?)'
            c2.execute(sql, (table_name, column, type))

        for index, columns in indices.iteritems():
            for column in columns:
                sql = 'INSERT INTO NOX_SCHEMA_INDEX' + \
                    '(NOX_TABLE, NOX_INDEX, NOX_COLUMN) VALUES (?, ?, ?)'
                c2.execute(sql, (table_name, index, column))

    c1.close()
    c2.close()
    
def main(argv=sys.argv):
    try:
        opts, args = getopt.getopt(argv[1:], 'hp:', ['help', 'plugin='])
        if len(args) != 1:
            print __doc__
            return 3

        plugin_dirs = [ ]
        for o, a in opts:
            if o in ('-h', '--help'):
                print __doc__
                return 3

            elif o in ('-p', '--plugin'):
                plugin_dirs.append(a)

        if len(plugin_dirs) == 0:
            plugin_dirs.append('.')
            
        old_database_file = args[0]
        fd, new_database_file = tempfile.mkstemp()
        fd, database_file_backup = tempfile.mkstemp()

        plugins = load_plugins(plugin_dirs)
        if plugins is None:
            return 1

        print '''Backing up the old database to '%s'.''' % database_file_backup
        shutil.copyfile(old_database_file, database_file_backup)

        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        old_database_conn = sqlite3.connect(old_database_file)
        old_database_conn.row_factory = dict_factory
        new_database_conn = sqlite3.connect(new_database_file)

        for table in load_tables(old_database_conn):
            migrate_table(table, plugins, old_database_conn, new_database_conn)

        old_database_conn.commit()
        new_database_conn.commit()

        os.rename(new_database_file, old_database_file)

        # Note as a safety measure the backup file is not deleted even
        # on success.  It's up to the user to delete it.
        return 0

    except Exception, e:
        print 'An error occurred.  All changes cancelled.'
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

__all__ = [ 'Plugin' ]
