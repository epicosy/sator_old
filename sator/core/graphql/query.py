import re
from typing import List

import graphene
import sqlalchemy

from graphene import ObjectType
# from graphql_relay import to_global_id

from sator.core.graphql.objects import CWE, CWEModel, Vulnerability, VulnerabilityModel, VulnerabilityCWE, \
    VulnerabilityCWEModel, Reference, Commit, ReferenceTagModel, Tag, TagModel, Repository, CommitModel, Configuration, \
    ConfigurationModel, Vendor, Product


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
    commits = graphene.Int()


class GrapheneCount(ObjectType):
    key = graphene.String()
    value = graphene.Int()


class NestedGrapheneCount(ObjectType):
    key = graphene.String()
    values = graphene.List(GrapheneCount)


class VulnerabilityNode(ObjectType):
    node = graphene.Field(Vulnerability)
    cursor = graphene.String()


class Pagination(ObjectType):
    hasNextPage = graphene.Boolean()
    hasPreviousPage = graphene.Boolean()
    startCursor = graphene.Int()
    endCursor = graphene.Int()
    totalPages = graphene.Int()
    totalResults = graphene.Int()
    page = graphene.Int()
    perPage = graphene.Int()
    pages = graphene.List(graphene.Int)


class VulnerabilitiesPage(Pagination):
    elements = graphene.List(Vulnerability)


class CommitsPage(Pagination):
    elements = graphene.List(Commit)


class RepositoriesPage(Pagination):
    elements = graphene.List(Repository)


class ConfigurationsPage(Pagination):
    elements = graphene.List(Configuration)


class VendorsPage(Pagination):
    elements = graphene.List(Vendor)


class ProductsPage(Pagination):
    elements = graphene.List(Product)


class Query(ObjectType):
    cwes = graphene.List(lambda: CWE, id=graphene.ID(), exists=graphene.Boolean())
    vulnerabilities = graphene.List(lambda: Vulnerability, id=graphene.ID(), first=graphene.Int(), skip=graphene.Int(),
                                    last=graphene.Int())
    counts = graphene.List(lambda: CWECounts)
    stats = graphene.Field(Stats)
    links = graphene.List(Link)
    assigners = graphene.List(lambda: GrapheneCount, company=graphene.Boolean())
    tags = graphene.List(lambda: GrapheneCount)
    vulns_by_year = graphene.List(GrapheneCount)
    vulnerabilities_page = graphene.Field(lambda: VulnerabilitiesPage, page=graphene.Int(), per_page=graphene.Int(),
                                          cwe_ids=graphene.List(graphene.Int), severity=graphene.List(graphene.String))
    commits_page = graphene.Field(lambda: CommitsPage, page=graphene.Int(), per_page=graphene.Int())
    repositories_page = graphene.Field(lambda: RepositoriesPage, page=graphene.Int(), per_page=graphene.Int())
    commit_kind_count = graphene.List(lambda: GrapheneCount)
    configurations_page = graphene.Field(lambda: ConfigurationsPage, page=graphene.Int(), per_page=graphene.Int())
    part_count = graphene.List(lambda: NestedGrapheneCount)
    vendors_page = graphene.Field(lambda: VendorsPage, page=graphene.Int(), per_page=graphene.Int())
    products_page = graphene.Field(lambda: ProductsPage, page=graphene.Int(), per_page=graphene.Int())

    def resolve_vulns_by_year(self, info):
        year_exp = sqlalchemy.extract('year', VulnerabilityModel.published_date)
        count_exp = sqlalchemy.func.count(VulnerabilityModel.published_date)
        vulns_by_year = Vulnerability.get_query(info).with_entities(year_exp, count_exp).group_by(year_exp).order_by(
            year_exp).all()

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

    def resolve_tags(self, info):
        query = Reference.get_query(info).join(ReferenceTagModel).join(TagModel)
        counts = {}

        for tag in Tag.get_query(info).all():
            tag_counts = query.filter(TagModel.name == tag.name).count()

            if tag not in counts:
                counts[tag.name] = tag_counts
            else:
                counts[tag.name] += tag_counts

        return [GrapheneCount(key=k, value=v) for k, v in counts.items()]

    def resolve_commit_kind_count(self, info):
        # the following counts the number of commits of each kind by the kind field
        query = Commit.get_query(info)
        counts = query.group_by(CommitModel.kind).with_entities(CommitModel.kind, sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_part_count(self, info):
        query = Configuration.get_query(info)

        vuln_cases = sqlalchemy.func.sum(sqlalchemy.case([(ConfigurationModel.vulnerable == True, 1)], else_=0))
        non_vuln_cases = sqlalchemy.func.sum(sqlalchemy.case([(ConfigurationModel.vulnerable == False, 1)], else_=0))

        counts = query.group_by(ConfigurationModel.part).with_entities(ConfigurationModel.part, vuln_cases,
                                                                       non_vuln_cases).all()

        return [NestedGrapheneCount(k, [GrapheneCount('vulnerable', v), GrapheneCount('non-vulnerable', n)]) for k, v, n in counts]

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
        commits = Commit.get_query(info).count()

        return Stats(total, labeled, references, commits)

    def resolve_counts(self, info):
        cwe_ids = CWE.get_query(info).all()

        all_counts = []
        for cwe in cwe_ids:
            cwe_counts = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.cwe_id == cwe.id).count()
            if cwe_counts > 0:
                all_counts.append(CWECounts(cwe.id, cwe_counts))

        return all_counts

    def resolve_cwes(self, info, id=None, exists: bool = False):
        query = CWE.get_query(info)

        if id:
            query = query.filter(CWEModel.id == id)

        if exists:
            # return CWEs that have vulnerabilities associated
            query = query.join(VulnerabilityCWEModel)

        return query.order_by('id').all()

    def resolve_vulnerabilities(self, info, id=None, first: int = None, skip: int = None, last: int = None, **kwargs):
        query = Vulnerability.get_query(info).order_by(VulnerabilityModel.published_date.desc())

        if id:
            return query.filter(VulnerabilityModel.id == id)
        query = query.all()

        if skip:
            query = query[skip:]

        if first:
            query = query[:first]

        elif last:
            query = query[:last]

        return query

    def resolve_vulnerabilities_page(self, info, page=1, per_page=10, cwe_ids: List[int] = None,
                                     severity: List[str] = None):
        query = Vulnerability.get_query(info).order_by('published_date')

        if cwe_ids:
            query = query.join(VulnerabilityCWEModel).join(CWEModel)
            # TODO: check if the cwe-ids exist in the database
            query = query.filter(CWEModel.id.in_(cwe_ids))
            query = query.filter(VulnerabilityCWEModel.vulnerability_id == VulnerabilityModel.id)

        if severity:
            query = query.filter(VulnerabilityModel.severity.in_(severity))

        vulnerabilities_pagination = query.paginate(page=page, per_page=per_page)

        vulnerabilities_page = VulnerabilitiesPage(
            hasNextPage=vulnerabilities_pagination.has_next,
            hasPreviousPage=vulnerabilities_pagination.has_prev,
            # startCursor=edges[0].cursor if edges else None,
            # endCursor=edges[-1].cursor if edges else None,
            totalPages=vulnerabilities_pagination.pages,
            totalResults=vulnerabilities_pagination.total,
            page=vulnerabilities_pagination.page,
            perPage=vulnerabilities_pagination.per_page,
            pages=list(
                vulnerabilities_pagination.iter_pages(left_edge=4, right_edge=4, left_current=5, right_current=5)),
            elements=[vulnerability for vulnerability in vulnerabilities_pagination.items]
        )

        return vulnerabilities_page

    def resolve_commits_page(self, info, page=1, per_page=10):
        query = Commit.get_query(info)
        commits_pagination = query.paginate(page=page, per_page=per_page)
        commits_page = CommitsPage(
            hasNextPage=commits_pagination.has_next,
            hasPreviousPage=commits_pagination.has_prev,
            totalPages=commits_pagination.pages,
            totalResults=commits_pagination.total,
            page=commits_pagination.page,
            perPage=commits_pagination.per_page,
            pages=list(commits_pagination.iter_pages(left_edge=4, right_edge=4, left_current=5, right_current=5)),
            elements=[commit for commit in commits_pagination.items]
        )

        return commits_page

    def resolve_repositories_page(self, info, page=1, per_page=10):
        query = Repository.get_query(info)
        repositories_pagination = query.paginate(page=page, per_page=per_page)
        repositories_page = RepositoriesPage(
            hasNextPage=repositories_pagination.has_next,
            hasPreviousPage=repositories_pagination.has_prev,
            totalPages=repositories_pagination.pages,
            totalResults=repositories_pagination.total,
            page=repositories_pagination.page,
            perPage=repositories_pagination.per_page,
            pages=list(repositories_pagination.iter_pages(left_edge=4, right_edge=4, left_current=5, right_current=5)),
            elements=[repository for repository in repositories_pagination.items]
        )

        return repositories_page

    def resolve_configurations_page(self, info, page=1, per_page=10):
        query = Configuration.get_query(info)
        configurations_pagination = query.paginate(page=page, per_page=per_page)
        configurations_page = ConfigurationsPage(
            hasNextPage=configurations_pagination.has_next,
            hasPreviousPage=configurations_pagination.has_prev,
            totalPages=configurations_pagination.pages,
            totalResults=configurations_pagination.total,
            page=configurations_pagination.page,
            perPage=configurations_pagination.per_page,
            pages=list(
                configurations_pagination.iter_pages(left_edge=4, right_edge=4, left_current=5, right_current=5)),
            elements=[configuration for configuration in configurations_pagination.items]
        )

        return configurations_page

    def resolve_vendors_page(self, info, page=1, per_page=10):
        query = Vendor.get_query(info)
        vendors_pagination = query.paginate(page=page, per_page=per_page)
        vendors_page = VendorsPage(
            hasNextPage=vendors_pagination.has_next,
            hasPreviousPage=vendors_pagination.has_prev,
            totalPages=vendors_pagination.pages,
            totalResults=vendors_pagination.total,
            page=vendors_pagination.page,
            perPage=vendors_pagination.per_page,
            pages=list(vendors_pagination.iter_pages(left_edge=4, right_edge=4, left_current=5, right_current=5)),
            elements=[vendor for vendor in vendors_pagination.items]
        )

        return vendors_page

    def resolve_products_page(self, info, page=1, per_page=10):
        query = Product.get_query(info)
        products_pagination = query.paginate(page=page, per_page=per_page)
        products_page = ProductsPage(
            hasNextPage=products_pagination.has_next,
            hasPreviousPage=products_pagination.has_prev,
            totalPages=products_pagination.pages,
            totalResults=products_pagination.total,
            page=products_pagination.page,
            perPage=products_pagination.per_page,
            pages=list(products_pagination.iter_pages(left_edge=4, right_edge=4, left_current=5, right_current=5)),
            elements=[product for product in products_pagination.items]
        )

        return products_page
