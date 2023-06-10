import graphene

from sqlalchemy import or_
from typing import List
from graphene.types.objecttype import ObjectType

from sator.core.graphql.objects import Vulnerability, Commit, Repository, Configuration, Vendor, Product, CommitFile, \
    CWEModel, VulnerabilityCWEModel, VulnerabilityModel, RepositoryModel


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


class CommitFilesPage(Pagination):
    elements = graphene.List(CommitFile)


class PaginationQuery(ObjectType):
    vulnerabilities_page = graphene.Field(lambda: VulnerabilitiesPage, page=graphene.Int(), per_page=graphene.Int(),
                                          cwe_ids=graphene.List(graphene.Int), severity=graphene.List(graphene.String))
    commits_page = graphene.Field(lambda: CommitsPage, page=graphene.Int(), per_page=graphene.Int())
    repositories_page = graphene.Field(lambda: RepositoriesPage, page=graphene.Int(), per_page=graphene.Int(),
                                       availability=graphene.List(graphene.Boolean),
                                       language=graphene.List(graphene.String))
    configurations_page = graphene.Field(lambda: ConfigurationsPage, page=graphene.Int(), per_page=graphene.Int())
    vendors_page = graphene.Field(lambda: VendorsPage, page=graphene.Int(), per_page=graphene.Int())
    products_page = graphene.Field(lambda: ProductsPage, page=graphene.Int(), per_page=graphene.Int())
    commit_files_page = graphene.Field(lambda: CommitFilesPage, page=graphene.Int(), per_page=graphene.Int())

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

    def resolve_repositories_page(self, info, page=1, per_page=10, availability: List[bool] = None,
                                  language: List[str] = None):
        query = Repository.get_query(info).order_by()

        if availability:
            query = query.filter(or_(RepositoryModel.available.in_(availability), RepositoryModel.available.is_(None)))

        if language:
            query = query.filter(RepositoryModel.language.in_(language))

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

    def resolve_commit_files_page(self, info, page=1, per_page=10):
        query = CommitFile.get_query(info)
        commit_files_pagination = query.paginate(page=page, per_page=per_page)
        commit_files_page = CommitFilesPage(
            hasNextPage=commit_files_pagination.has_next,
            hasPreviousPage=commit_files_pagination.has_prev,
            totalPages=commit_files_pagination.pages,
            totalResults=commit_files_pagination.total,
            page=commit_files_pagination.page,
            perPage=commit_files_pagination.per_page,
            pages=list(commit_files_pagination.iter_pages(left_edge=4, right_edge=4, left_current=5, right_current=5)),
            elements=[commit_file for commit_file in commit_files_pagination.items]
        )

        return commit_files_page
