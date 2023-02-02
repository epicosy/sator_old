import pkg_resources

__version__ = pkg_resources.get_distribution('sator').version

from flask import Flask
from flask_graphql import GraphQLView

from sator.core.graphql.schema import schema


def create_flask_app(configs: dict):
    flask_app = Flask(__name__)
    flask_app.config.update(configs)

    @flask_app.route("/")
    def index():
        return f"Sator ({__version__}) API"

    flask_app.add_url_rule(
        '/graphql',
        view_func=GraphQLView.as_view(
            'graphql',
            schema=schema,
            graphiql=True
        )
    )

    return flask_app
