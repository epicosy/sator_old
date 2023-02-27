from pathlib import Path

from cement import Controller, ex

from sator import create_flask_app, __version__

VERSION_BANNER = """ vulnerability database api (v%s)""" % __version__


class Base(Controller):
    class Meta:
        label = 'base'

        # text displayed at the top of --help output
        description = 'vulnerability database api'

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator run'

        # controller level arguments. ex: 'sator --version'
        arguments = [
            (['-v', '--version'], {'action': 'version', 'version': VERSION_BANNER}),
        ]

    def _default(self):
        """Default action if no sub-command is passed."""

        self.app.args.print_help()

    @ex(
        help='Launches the server API',
        arguments=[
            (['-p', '--port'], {'help': 'Port for server. (Overwrites config port)', 'type': int, 'required': False}),
            (['-a', '--address'], {'help': 'IPv4 host address for server. ', 'type': str, 'default': 'localhost'})
        ]
    )
    def run(self):
        """Example sub-command."""

        if self.app.config.has_section('flask'):
            flask_configs = {k.upper(): v for k, v in self.app.config.get_dict()['flask'].items()}
        else:
            flask_configs = {}

        if self.app.pargs.port:
            flask_configs['RUN_PORT'] = self.app.pargs.port
        elif 'RUN_PORT' not in flask_configs:
            flask_configs['RUN_PORT'] = 3000
            self.app.log.warning("No port number specified, setting default port number to '3000'")

        if 'DEBUG' not in flask_configs:
            flask_configs['DEBUG'] = self.app.config.get('sator', 'debug')

        flask_app = create_flask_app(configs=flask_configs)

        # setup database
        tables_path = Path(__file__).parent.parent / 'config' / 'tables'
        from sator.core.models import init_flask_db
        init_flask_db(tables_path, flask_app, self.app.log)

        flask_app.run(debug=flask_configs['DEBUG'], port=flask_configs['RUN_PORT'], host=self.app.pargs.address)

    @ex(
        help='Gets data from NVD'
    )
    def nvd(self):

        if self.app.config.has_section('flask'):
            flask_configs = {k.upper(): v for k, v in self.app.config.get_dict()['flask'].items()}
        else:
            flask_configs = {}

        if 'RUN_PORT' not in flask_configs:
            flask_configs['RUN_PORT'] = 3000
            self.app.log.warning("No port number specified, setting default port number to '3000'")

        if 'DEBUG' not in flask_configs:
            flask_configs['DEBUG'] = self.app.config.get('sator', 'debug')

        flask_app = create_flask_app(configs=flask_configs)

        # setup database
        tables_path = Path(__file__).parent.parent / 'config' / 'tables'
        from sator.core.models import init_flask_db
        init_flask_db(tables_path, flask_app, self.app.log)

        self.app.extend('flask_app', flask_app)
#        # setup database
#        tables_path = Path(__file__).parent.parent / 'config' / 'tables'
#        from sator.core.models import init_db
#        init_db(self.app.config.get('flask', 'SQLALCHEMY_DATABASE_URI'), tables_path, self.app.log)

        nvd_handler = self.app.handler.get('handlers', 'nvd', setup=True)
        nvd_handler.run()
