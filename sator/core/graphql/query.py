import re
from sqlalchemy.orm import aliased

import graphene
import sqlalchemy

from graphene import ObjectType
# from graphql_relay import to_global_id
from graphql import GraphQLError

from sator.core.graphql.objects import CWE, CWEModel, Vulnerability, VulnerabilityModel, VulnerabilityCWE, \
    VulnerabilityCWEModel, Reference, Commit, ReferenceTagModel, Tag, TagModel, Repository, CommitModel, Configuration, \
    ConfigurationModel, Product, RepositoryModel, CommitFile, CommitFileModel, ProductModel, VendorModel, \
    ProductTypeModel, RepositoryTopicModel, TopicModel, ConfigurationVulnerabilityModel, Grouping, GroupingModel, \
    DatasetVulnerability, DatasetVulnerabilityModel, RepositoryProductType, ProductType, \
    RepositoryProductTypeModel, GrapheneCount

from sator.core.graphql.queries.pagination import PaginationQuery
from sator.core.graphql.queries.objects import ObjectsQuery


def extract_company(email: str):
    return re.findall(r"\@(.*?)\.", email)[0]


class Link(ObjectType):
    at = graphene.String()
    to = graphene.String()
    count = graphene.Int()


class Stats(ObjectType):
    total = graphene.Int()
    labeled = graphene.Int()
    references = graphene.Int()
    commits = graphene.Int()


class NestedGrapheneCount(ObjectType):
    key = graphene.String()
    values = graphene.List(GrapheneCount)


class VulnerabilityNode(ObjectType):
    node = graphene.Field(Vulnerability)
    cursor = graphene.String()


class Query(ObjectsQuery, PaginationQuery, ObjectType):
    stats = graphene.Field(Stats)
    links = graphene.List(Link)
    assigners = graphene.List(lambda: GrapheneCount, company=graphene.Boolean())
    tags = graphene.List(lambda: GrapheneCount)
    vulns_by_year = graphene.List(GrapheneCount)
    configs_part_count = graphene.List(lambda: NestedGrapheneCount)
    commits_stats = graphene.List(lambda: GrapheneCount)
    commit_kind_count = graphene.List(lambda: GrapheneCount)
    repositories_commits_frequency = graphene.List(lambda: GrapheneCount)
    repositories_availability = graphene.List(lambda: GrapheneCount)
    commits_availability = graphene.List(lambda: GrapheneCount)
    commits_state = graphene.List(lambda: GrapheneCount)
    cwe_counts = graphene.List(lambda: GrapheneCount)
    vulns_severity = graphene.List(lambda: GrapheneCount)
    vulns_exploitability = graphene.List(lambda: GrapheneCount)
    commits_files_count = graphene.List(lambda: GrapheneCount)
    commits_changes_count = graphene.List(lambda: GrapheneCount)
    files_extensions = graphene.List(lambda: GrapheneCount)
    files_changes_count = graphene.List(lambda: GrapheneCount)
    files_statuses = graphene.List(lambda: GrapheneCount)
    repositories_language_count = graphene.List(lambda: GrapheneCount)
    configs_vulns_count = graphene.List(lambda: GrapheneCount)
    products_count_by_vendor = graphene.List(lambda: GrapheneCount)
    configs_count_by_vendor = graphene.List(lambda: GrapheneCount)
    vulns_count_by_vendor = graphene.List(lambda: GrapheneCount)
    configs_count_by_product = graphene.List(lambda: GrapheneCount)
    vulns_count_by_product = graphene.List(lambda: GrapheneCount)
    sw_type_count = graphene.List(lambda: GrapheneCount)
    language_extension_links_count = graphene.List(lambda: Link, filter_counts=graphene.Int())
    topics_count = graphene.List(lambda: GrapheneCount)
    lang_product_links_count = graphene.List(lambda: Link, filter_counts=graphene.Int())
    cwe_multiplicity = graphene.List(lambda: GrapheneCount)
    vulns_count_by_sof_dev_view = graphene.List(lambda: GrapheneCount)
    search_vulnerability = graphene.List(lambda: Vulnerability, keyword=graphene.String(), limit=graphene.Int())
    datasets_overlap = graphene.Float(src_id=graphene.Int(), tgt_id=graphene.Int())
    repositories_software_type_count = graphene.List(lambda: GrapheneCount)
    sw_type_vulnerability_profile = graphene.List(lambda: GrapheneCount, sw_type=graphene.String(),
                                                  repo_id=graphene.String())

    def resolve_sw_type_vulnerability_profile(self, info, sw_type: str, repo_id: str = None):
        sw_type = ProductType.get_query(info).filter(ProductTypeModel.name == sw_type).first()

        if not sw_type:
            raise GraphQLError(f"Software type {sw_type} not found")

        # TODO: refactor this to be done in the query
        repos_ids = RepositoryProductType.get_query(info).filter(RepositoryProductTypeModel.product_type_id == sw_type.id).all()
        to_exclude = None

        if repo_id:
            repo = Repository.get_query(info).filter(RepositoryModel.id == repo_id).first()

            if repo:
                to_exclude = repo.id

        repos = Repository.get_query(info).filter(RepositoryModel.id.in_([r.repository_id for r in repos_ids if r.repository_id != to_exclude])).all()

        commits = [c for r in repos for c in r.commits]
        vulns = [c.vulnerability_id for c in commits]
        cwes = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.vulnerability_id.in_(vulns)).\
            group_by(VulnerabilityCWEModel.cwe_id).\
            with_entities(VulnerabilityCWEModel.cwe_id, sqlalchemy.func.count(VulnerabilityCWEModel.cwe_id)).all()

        return [GrapheneCount(key=cwe, value=count) for cwe, count in cwes]

    def resolve_repositories_software_type_count(self, info):
        count = RepositoryProductType.get_query(info).join(ProductTypeModel).group_by(ProductTypeModel.name).\
            with_entities(ProductTypeModel.name, sqlalchemy.func.count(ProductTypeModel.name)).all()

        return [GrapheneCount(key=k, value=v) for k, v in count]

    def resolve_datasets_overlap(self, info, src_id: int, tgt_id: int):
        src_dataset_vulns = DatasetVulnerability.get_query(info).filter(DatasetVulnerabilityModel.dataset_id == src_id).all()
        tgt_dataset_vulns = DatasetVulnerability.get_query(info).filter(DatasetVulnerabilityModel.dataset_id == tgt_id).all()
        src_dataset_vulns_ids = [x.vulnerability_id for x in src_dataset_vulns]
        tgt_dataset_vulns_ids = [x.vulnerability_id for x in tgt_dataset_vulns]
        overlap = set(src_dataset_vulns_ids).intersection(set(tgt_dataset_vulns_ids))

        if len(overlap) == 0:
            return 0

        if len(src_dataset_vulns_ids) == 0:
            return 0

        return len(overlap)/len(src_dataset_vulns_ids)*100

    def resolve_search_vulnerability(self, info, keyword: str, limit: int = 10):
        return Vulnerability.get_query(info).filter(VulnerabilityModel.id.ilike(f'%{keyword}%'))\
            .limit(limit).all()

    def resolve_vulns_count_by_sof_dev_view(self, info):
        sof_dev_categories = Grouping.get_query(info).filter(GroupingModel.parent_id == 699).all()
        categories_id = [x.child_id for x in sof_dev_categories]

        cwe_category = dict(Grouping.get_query(info).filter(GroupingModel.parent_id.in_(categories_id)).\
            with_entities(GroupingModel.child_id, GroupingModel.parent_id).all())

        query = Vulnerability.get_query(info).join(VulnerabilityCWEModel).filter(VulnerabilityCWEModel.cwe_id.in_(cwe_category.keys()))\
            .group_by(VulnerabilityCWEModel.cwe_id).with_entities(VulnerabilityCWEModel.cwe_id, sqlalchemy.func.count().label('count')).all()

        categories_count = {}

        for k, v in query:
            category = cwe_category[k]

            if category not in categories_count:
                categories_count[category] = 0

            categories_count[category] += v

        cwes_name = dict(CWE.get_query(info).filter(CWEModel.id.in_(categories_count.keys())).\
                         with_entities(CWEModel.id, CWEModel.name).all())

        return [GrapheneCount(key=f"CWE-{k}: {cwes_name[k]}", value=v) for k, v in categories_count.items()]

    def resolve_cwe_multiplicity(self, info):
        subquery = VulnerabilityCWE.get_query(info).join(VulnerabilityModel).group_by(VulnerabilityCWEModel.vulnerability_id)\
            .with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = VulnerabilityCWE.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count))\
            .group_by(subquery.c.count). order_by(subquery.c.count)

        count_of_counts = query.all()

        return [GrapheneCount(key=k, value=v) for k, v in count_of_counts]


    def resolve_sw_type_count(self, info):
        query = Product.get_query(info).join(ProductTypeModel)
        counts = query.group_by(ProductTypeModel.name).with_entities(ProductTypeModel.name, sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_cwe_counts(self, info):
        cwe_counts = Vulnerability.get_query(info).join(VulnerabilityCWEModel).join(CWEModel).group_by(CWEModel.id).\
            with_entities(CWEModel.id, sqlalchemy.func.count()).order_by(CWEModel.id).all()

        return [GrapheneCount(key=k, value=v) for k, v in cwe_counts]

    def resolve_commit_kind_count(self, info):
        # the following counts the number of commits of each kind by the kind field
        query = Commit.get_query(info)
        counts = query.group_by(CommitModel.kind).with_entities(CommitModel.kind, sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_vulns_severity(self, info):
        # the following counts the number of vulnerabilities of each severity by the severity field
        query = Vulnerability.get_query(info)
        counts = query.group_by(VulnerabilityModel.severity).with_entities(VulnerabilityModel.severity,
                                                                           sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'N/A', value=v) for k, v in counts]

    def resolve_vulns_exploitability(self, info):
        # the following counts the number of vulnerabilities of each exploitability by the exploitability field
        query = Vulnerability.get_query(info)
        counts = query.group_by(VulnerabilityModel.exploitability).with_entities(VulnerabilityModel.exploitability,
                                                                           sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'N/A', value=v) for k, v in counts]

    def resolve_repositories_availability(self, info):
        # the following counts the number of repositories of each availability by the availability field
        query = Repository.get_query(info)
        counts = query.group_by(RepositoryModel.available).with_entities(RepositoryModel.available,
                                                                         sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'awaiting', value=v) for k, v in counts]

    def resolve_repositories_language_count(self, info):
        # the following counts the number of repositories of each language by the language field
        query = Repository.get_query(info)
        counts = query.group_by(RepositoryModel.language).with_entities(RepositoryModel.language,
                                                                        sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_commits_availability(self, info):
        # the following counts the number of commits of each availability by the availability field
        query = Commit.get_query(info)
        counts = query.group_by(CommitModel.available).with_entities(CommitModel.available,
                                                                     sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'awaiting', value=v) for k, v in counts]

    def resolve_commits_state(self, info):
        # the following counts the number of commits of each state by the state field
        query = Commit.get_query(info)
        counts = query.group_by(CommitModel.state).with_entities(CommitModel.state,
                                                                 sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'awaiting', value=v) for k, v in counts]

    def resolve_repositories_commits_frequency(self, info):
        subquery = Commit.get_query(info).filter(CommitModel.kind != 'parent').group_by(CommitModel.repository_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Commit.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count))\
            .group_by(subquery.c.count). order_by(subquery.c.count)

        count_of_counts = query.all()

        return [GrapheneCount(key=k, value=v) for k, v in count_of_counts]

    def resolve_commits_files_count(self, info):
        query = Commit.get_query(info).group_by(CommitModel.files_count).\
            with_entities(CommitModel.files_count, sqlalchemy.func.count(CommitModel.files_count))\
            .order_by(CommitModel.files_count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_commits_changes_count(self, info):
        query = Commit.get_query(info).group_by(CommitModel.changes).\
            with_entities(CommitModel.changes, sqlalchemy.func.count(CommitModel.changes))\
            .order_by(CommitModel.changes).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_files_extensions(self, info):
        query = CommitFile.get_query(info).group_by(CommitFileModel.extension).\
            with_entities(CommitFileModel.extension, sqlalchemy.func.count(CommitFileModel.extension))\
            .order_by(CommitFileModel.extension).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_files_changes_count(self, info):
        query = CommitFile.get_query(info).group_by(CommitFileModel.changes).\
            with_entities(CommitFileModel.changes, sqlalchemy.func.count(CommitFileModel.changes))\
            .order_by(CommitFileModel.changes).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_files_statuses(self, info):
        query = CommitFile.get_query(info).group_by(CommitFileModel.status).\
            with_entities(CommitFileModel.status, sqlalchemy.func.count(CommitFileModel.status)).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_vulns_by_year(self, info):
        year_exp = sqlalchemy.extraccwet('year', VulnerabilityModel.published_date)
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

    def resolve_configs_part_count(self, info):
        query = Configuration.get_query(info)

        vuln_cases = sqlalchemy.func.sum(sqlalchemy.case([(ConfigurationModel.vulnerable == True, 1)], else_=0))
        non_vuln_cases = sqlalchemy.func.sum(sqlalchemy.case([(ConfigurationModel.vulnerable == False, 1)], else_=0))

        counts = query.group_by(ConfigurationModel.part).with_entities(ConfigurationModel.part, vuln_cases,
                                                                       non_vuln_cases).all()

        return [NestedGrapheneCount(k, [GrapheneCount('vulnerable', v), GrapheneCount('non-vulnerable', n)]) for k, v, n in counts]

    def resolve_configs_vulns_count(self, info):
        subquery = Vulnerability.get_query(info) \
            .outerjoin(ConfigurationVulnerabilityModel, VulnerabilityModel.id == ConfigurationVulnerabilityModel.vulnerability_id) \
            .group_by(VulnerabilityModel.id) \
            .with_entities(sqlalchemy.func.coalesce(sqlalchemy.func.count(ConfigurationVulnerabilityModel.configuration_id), 0).label('count'))\
            .subquery()

        counts = Vulnerability.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_products_count_by_vendor(self, info):
        subquery = Product.get_query(info).join(VendorModel).group_by(ProductModel.vendor_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Product.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_configs_count_by_vendor(self, info):
        subquery = Configuration.get_query(info).join(VendorModel).group_by(ConfigurationModel.vendor_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Configuration.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_vulns_count_by_vendor(self, info):
        subquery = Vulnerability.get_query(info).join(ConfigurationModel).group_by(ConfigurationModel.vendor_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Vulnerability.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_configs_count_by_product(self, info):
        subquery = Product.get_query(info)\
            .outerjoin(ConfigurationModel, ProductModel.id == ConfigurationModel.product_id) \
            .group_by(ProductModel.id) \
            .with_entities(sqlalchemy.func.coalesce(sqlalchemy.func.count(ConfigurationModel.product_id), 0).label('count'))\
            .subquery()

        query = Product.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)) \
            .group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_vulns_count_by_product(self, info):
        subquery = Configuration.get_query(info).group_by(ConfigurationModel.product_id)\
            .with_entities(sqlalchemy.func.coalesce(sqlalchemy.func.count(ConfigurationModel.vulnerability_id), 0).label('count')) \
            .subquery()

        query = Configuration.get_query(info) \
            .with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)) \
            .group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_language_extension_links_count(self, info, filter_counts: int = None):
        query = Repository.get_query(info).join(CommitModel).join(CommitFileModel)\
            .group_by(RepositoryModel.language, CommitFileModel.extension)\
            .with_entities(RepositoryModel.language, CommitFileModel.extension, sqlalchemy.func.count()).all()

        if filter_counts:
            return [Link(at=at, to=to, count=count) for at, to, count in query if count >= filter_counts]

        return [Link(at=at, to=to, count=count) for at, to, count in query]

    def resolve_topics_count(self, info):
        query = Repository.get_query(info).join(RepositoryTopicModel).join(TopicModel)\
            .group_by(TopicModel.name).with_entities(TopicModel.name, sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_lang_product_links_count(self, info, filter_counts: int = None):
        query = Repository.get_query(info).join(CommitModel).join(VulnerabilityModel).join(ConfigurationModel)\
            .join(ProductModel).join(ProductTypeModel).filter(RepositoryModel.language != None)\
            .group_by(RepositoryModel.language, ProductTypeModel.name)\
            .with_entities(RepositoryModel.language, ProductTypeModel.name, sqlalchemy.func.count()).all()

        if filter_counts:
            return [Link(at=at, to=to, count=count) for at, to, count in query if count > filter_counts]

        return [Link(at=at, to=to, count=count) for at, to, count in query]

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
