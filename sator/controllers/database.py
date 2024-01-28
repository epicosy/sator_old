from pathlib import Path

from cement import Controller, ex


class Database(Controller):
    class Meta:
        label = 'database'

        stacked_on = 'base'
        stacked_type = 'nested'

        # text displayed at the top of --help output
        description = 'database controller'

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator database'

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Initialize the database'
    )
    def init(self):

        """Init sub-command."""
        tables_path = Path(__file__).parent.parent / 'config' / 'tables'
        from sator.core.models import init_db

        init_db(self.app.flask_configs.get('SQLALCHEMY_DATABASE_URI'), tables_path, self.app.log)
