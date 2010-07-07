from nox.apps.migration.migration import Plugin

class Example_plugin(Plugin):
    """
    An example plugin migrating a table 'TEST' from version 0 to 1.
    """
    def get_table(self): return 'EXAMPLE_TABLE'
    def get_version(self): return 0
    def get_schema(self): return \
    [
        {
            'GUID' : self.GUID,
            'COLUMN_A' : self.TEXT,
            'COLUMN_B' : self.INTEGER,
            'COLUMN_NEW' : self.INTEGER
        },
        {
            'EXAMPLE_TABLE_INDEX_1' : ( 'COLUMN_A', ),
        }
    ]

    def migrate(self, row):
        """
        Set the default value to the new column.
        """
        row['COLUMN_NEW'] = 0
        return row

def get_plugins():
    return [ Example_plugin() ]

__all__ = [ 'get_plugins' ]
