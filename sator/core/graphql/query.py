import graphene
from graphene import ObjectType, Node
from sator.core.graphql.objects import CWE, CWEModel


class Query(ObjectType):
    cwe = Node.Field(CWE)
    cwes = graphene.List(lambda: CWE, id=graphene.ID())

    def resolve_cwes(self, info, id=None):
        query = CWE.get_query(info)

        if id:
            query = query.filter(CWEModel.id == id)

        return query.all()
