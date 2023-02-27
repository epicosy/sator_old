import re
import graphene
import sqlalchemy

from graphene import ObjectType

from sator.core.graphql.objects import CWE, CWEModel, Vulnerability, VulnerabilityModel, VulnerabilityCWE, \
    VulnerabilityCWEModel, Reference


def extract_company(email: str):
    return re.findall(r"\@(.*?)\.", email)[0]


class Link(ObjectType):
    at = graphene.String()
    to = graphene.String()
    count = graphene.Int()


class CWECounts(ObjectType):
    cwe = graphene.Int()
    count = graphene.Int()


class Stats(ObjectType):
    total = graphene.Int()
    labeled = graphene.Int()
    references = graphene.Int()


class GrapheneCount(ObjectType):
    key = graphene.String()
    value = graphene.Int()


class Query(ObjectType):
    cwes = graphene.List(lambda: CWE, id=graphene.ID())
    vulnerabilities = graphene.List(lambda: Vulnerability, id=graphene.ID(), first=graphene.Int(), skip=graphene.Int(),
                                    last=graphene.Int())
    counts = graphene.List(lambda: CWECounts)
    stats = graphene.Field(Stats)
    links = graphene.List(Link)
    assigners = graphene.List(lambda: GrapheneCount, company=graphene.Boolean())
    vulns_by_year = graphene.List(GrapheneCount)

    def resolve_vulns_by_year(self, info):
        year_exp = sqlalchemy.extract('year', VulnerabilityModel.published_date)
        count_exp = sqlalchemy.func.count(VulnerabilityModel.published_date)
        vulns_by_year = Vulnerability.get_query(info).with_entities(year_exp, count_exp).group_by(year_exp).order_by(year_exp).all()

        return [GrapheneCount(key=k, value=v) for k, v in vulns_by_year]

    def resolve_assigners(self, info, company: bool = False):
        assigners = Vulnerability.get_query(info).distinct(VulnerabilityModel.assigner)
        counts = {}

        for vuln in assigners:
            assigner_counts = Vulnerability.get_query(info).filter(VulnerabilityModel.assigner == vuln.assigner).count()

            assigner = extract_company(vuln.assigner) if company else vuln.assigner

            if assigner not in counts:
                counts[assigner] = assigner_counts
            else:
                counts[assigner] += assigner_counts

        return [GrapheneCount(key=k, value=v) for k, v in counts.items()]

    def resolve_links(self, info):
        cwe_ids = CWE.get_query(info).all()
        mapping = {}

        for cwe in cwe_ids:
            cwe_counts = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.cwe_id == cwe.id).count()

            if cwe_counts < 1:
                continue

            bf_classes = CWE.resolve_bf_class(cwe, info)
            phases = CWE.resolve_phases(cwe, info)
            operations = CWE.resolve_operations(cwe, info)

            if len(bf_classes) > 1:
                continue

            if bf_classes[0].name == "None":
                continue

            if len(phases) > 1:
                continue

            link_name = f"{bf_classes[0].name}_{phases[0].name}"

            if link_name not in mapping:
                mapping[link_name] = Link(bf_classes[0].name, phases[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

            if len(operations) > 1:
                continue

            link_name = f"{phases[0].name}_{operations[0].name}"

            if link_name not in mapping:
                mapping[link_name] = Link(phases[0].name, operations[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

        return list(mapping.values())

    def resolve_stats(self, info):
        total = Vulnerability.get_query(info).count()
        references = Reference.get_query(info).count()
        labeled = VulnerabilityCWE.get_query(info).count()

        return Stats(total, labeled, references)

    def resolve_counts(self, info):
        cwe_ids = CWE.get_query(info).all()

        all_counts = []
        for cwe in cwe_ids:
            cwe_counts = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.cwe_id == cwe.id).count()
            if cwe_counts > 0:
                all_counts.append(CWECounts(cwe.id, cwe_counts))

        return all_counts

    def resolve_cwes(self, info, id=None):
        query = CWE.get_query(info)

        if id:
            query = query.filter(CWEModel.id == id)

        return query.all()

    def resolve_vulnerabilities(self, info, id=None, first: int = None, skip: int = None, last: int = None, **kwargs):
        query = Vulnerability.get_query(info).order_by('published_date')

        if id:
            return query.filter(VulnerabilityModel.id == id)

        if skip:
            query = query.all()[skip:]

        if first:
            if not isinstance(query, list):
                query = query.all()

            query = query[:first]
        elif last:
            query = query.order_by(VulnerabilityModel.published_date.desc())[:last]

        return query
