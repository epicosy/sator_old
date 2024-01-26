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

    def __init__(self, **kw):
        super().__init__(**kw)
        self.flask_configs = {}

    def _post_argument_parsing(self):
        super()._post_argument_parsing()

        if self.app.config.has_section('flask'):
            self.flask_configs = {k.upper(): v for k, v in self.app.config.get_dict()['flask'].items()}

        _port = self.flask_configs.get('RUN_PORT')

        if self.app.pargs.port:
            if _port:
                self.app.log.warning(f"Overwriting config port number from {_port} to '{self.app.pargs.port}'")
            self.flask_configs['RUN_PORT'] = self.app.pargs.port
        elif _port:
            self.app.log.warning(f"Using port number from config '{_port}'")
        else:
            self.app.log.warning("No port number specified, setting default port number to '3000'")
            self.flask_configs['RUN_PORT'] = 3000

        if 'DEBUG' not in self.flask_configs:
            self.flask_configs['DEBUG'] = self.app.config.get('sator', 'debug')

        flask_app = create_flask_app(configs=self.flask_configs)

        # setup database
        tables_path = Path(__file__).parent.parent / 'config' / 'tables'
        from sator.core.models import init_flask_db

        if self.app.pargs.uri is "":
            self.app.log.warning(f"Provided URI is empty")

        self.app.log.warning(f"Using URI: {self.app.pargs.uri}")

        init_flask_db(tables_path, flask_app, self.app.log, self.app.pargs.uri)

        self.app.extend('flask_app', flask_app)

    def _default(self):
        """Default action if no sub-command is passed."""

        self.app.args.print_help()

    @ex(
        help='Launches the server API',
        arguments=[
            (['-p', '--port'], {'help': 'Port for server. (Overwrites config port)', 'type': int, 'required': False}),
            (['-a', '--address'], {'help': 'IPv4 host address for server. ', 'type': str, 'default': 'localhost'}),
            (['-u', '--uri'], {'help': 'URI for database. (Overwrites config uri)', 'type': str, 'required': False})
        ]
    )
    def run(self):
        """Run sub-command."""

        self.app.flask_app.run(debug=self.flask_configs['DEBUG'], port=self.flask_configs['RUN_PORT'],
                               host=self.app.pargs.address)

    @ex(
        help='Gets data from NVD'
    )
    def nvd(self):
        self.app.handler.get('handlers', 'nvd', setup=True).run()

    @ex(
        help='Gets data from GitHub',
        arguments=[
            (['-gt', '--tokens'], {'help': 'Comma-separated list of tokens for the GitHub API.', 'type': str,
                                   'required': True}),
        ]
    )
    def metadata(self):
        """Metadata sub-command."""
        self.app.handler.get('handlers', 'nvd', setup=True).add_metadata()

    @ex(
        help='Generates with OpenAI API the software type for each repository in the database',
        arguments=[
            (['-gt', '--tokens'], {'help': 'Comma-separated list of tokens for the GitHub API.', 'type': str,
                                   'required': True}),
            (['-ot', '--openai-token'], {'help': 'Token for the OpenAI API.', 'type': str, 'required': True}),
            (['-m', '--model'], {'help': 'Model to use for the OpenAI API.', 'type': str, 'default': 'gpt-3.5-turbo'}),
        ])
    def generate(self):
        """Generate sub-command."""
        self.app.handler.get('handlers', 'openai', setup=True).generate()
