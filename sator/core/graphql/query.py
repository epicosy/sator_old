from sqlalchemy.orm import aliased

import graphene
import sqlalchemy
from sqlalchemy.sql import func
from graphene import ObjectType
from graphql import GraphQLError
# from graphql_relay import to_global_id
from sator.core.graphql.objects import GrapheneCount
from sator.core.graphql.objects import CWE, Vulnerability, VulnerabilityModel, VulnerabilityCWE, CommitFileModel, \
    VulnerabilityCWEModel, CVSS3Model, CVSS2Model, Reference, Commit, Repository, CommitModel, ConfigurationModel, RepositoryModel, \
    ProductModel, ProductTypeModel, DatasetVulnerability, DatasetVulnerabilityModel, Line, LineModel, Function,\
    FunctionModel

from sator.core.graphql.queries.pagination import PaginationQuery
from sator.core.graphql.queries.objects import ObjectsQuery
from sator.core.graphql.queries.counts import CountsQuery
from sator.utils.misc import JavaMethodExtractor


class Link(ObjectType):
    at = graphene.String()
    to = graphene.String()
    count = graphene.Int()


class Stats(ObjectType):
    total = graphene.Int()
    labeled = graphene.Int()
    references = graphene.Int()
    commits = graphene.Int()


class VulnerabilityNode(ObjectType):
    node = graphene.Field(Vulnerability)
    cursor = graphene.String()


class Position(ObjectType):
    line = graphene.Int()
    column = graphene.Int()


class MethodBoundary(ObjectType):
    name = graphene.String()
    start = graphene.Field(lambda: Position)
    end = graphene.Field(lambda: Position)
    code = graphene.List(graphene.String)

class ProfileCount(ObjectType):
    total = graphene.Int()
    year = graphene.List(lambda: GrapheneCount)
    cwe = graphene.List(lambda: GrapheneCount)
    score = graphene.List(lambda: GrapheneCount)

class Query(CountsQuery, ObjectsQuery, PaginationQuery, ObjectType):
    stats = graphene.Field(Stats)
    links = graphene.List(Link)

    language_extension_links_count = graphene.List(lambda: Link, filter_counts=graphene.Int())
    lang_product_links_count = graphene.List(lambda: Link, filter_counts=graphene.Int())

    search_vulnerability = graphene.List(lambda: Vulnerability, keyword=graphene.String(), limit=graphene.Int())
    datasets_overlap = graphene.Float(src_id=graphene.Int(), tgt_id=graphene.Int())
    functions = graphene.List(lambda: MethodBoundary, file_id=graphene.String())
     
    # profile_count = graphene.Field(lambda: ProfileCount, start_year = graphene.Int(), end_year= graphene.Int(), cwe_ids= graphene.List(graphene.Int),
    #                         start_score= graphene.Float(), end_score= graphene.Float(), has_code= graphene.Boolean(),
    #                         has_exploit= graphene.Boolean(), has_advisory= graphene.Boolean())

    profile_count = graphene.Field(
        lambda: ProfileCount,
        start_year=graphene.Int(),
        end_year=graphene.Int(),
        cwe_ids=graphene.List(graphene.Int),
        start_exp_score=graphene.Float(),
        end_exp_score=graphene.Float(),
        has_commit=graphene.Boolean(),
        has_exploit=graphene.Boolean(),
        has_advisory=graphene.Boolean(),
        vul_type=graphene.Boolean(),
        num_lines=graphene.Int(),
        extension=graphene.String(),
        num_files=graphene.Int(),
        language=graphene.String(),
        repo_size=graphene.Int()
    )

    def resolve_functions(self, info, file_id: str):
        return Function.get_query(info).filter_by(commit_file_id=file_id).order_by(FunctionModel.start).all()
    

    def resolve_profile_count(self, info, start_year: int = None, end_year: int = None, 
                              vul_type:bool=False, has_commit:bool=False,has_exploit: bool = False,
                              has_advisory: bool = False,
                              start_exp_score: float = None, end_exp_score: float = None,
                              num_lines:int=0, extension:str="",num_files:int=0,
                              language:str="",repo_size:int=0, 
                              cwe_ids: list[int] = None
                              
                             ):
        

        query = Vulnerability.get_query(info)

        if has_commit:
            # Subquery to check if there are any commits related to the vulnerability
            subquery = (
                Commit.get_query(info)
                .filter(CommitModel.vulnerability_id == VulnerabilityModel.id)
                .exists()
            )

            # Apply the exists condition to the main query
            query = query.filter(subquery)

        # check if start_year and end_year are valid
        if start_year and end_year and start_year > end_year:
            raise GraphQLError("Invalid date range")

        # check if start_score and end_score are valid
        if start_exp_score and end_exp_score and start_exp_score > end_exp_score:
            raise GraphQLError("Invalid score range")

        if start_year:
            query = query.filter(VulnerabilityModel.published_date >= f'{start_year}-01-01')

        if end_year:
            query = query.filter(VulnerabilityModel.published_date <= f'{end_year}-12-31')

        if cwe_ids:
            query = query.join(VulnerabilityCWEModel).filter(VulnerabilityCWEModel.cwe_id.in_(cwe_ids))
        # Filtering by score range using CVSS3  scores
        if start_exp_score is not None or end_exp_score is not None:
            query = query.join(CVSS3Model)  
            if start_exp_score is not None:
                query = query.filter(CVSS3Model.exploitabilityScore >= start_exp_score)
            if end_exp_score is not None:
                query = query.filter(CVSS3Model.exploitabilityScore <= end_exp_score)


        if language:
      
            commit_language_subquery = (
                Commit.get_query(info)
                .join(Repository, Repository.id == CommitModel.repository_id)  # Adjust with correct foreign key column
                .filter(Repository.language == language)
                .filter(CommitModel.vulnerability_id == VulnerabilityModel.id)
                .exists()
            )

            # Apply the refined subquery
            query = query.filter(commit_language_subquery)

        year_counts = query.group_by(
            func.extract('year', VulnerabilityModel.published_date)
        ).with_entities(
            func.extract('year', VulnerabilityModel.published_date).label('year'),
            func.count().label('count')
        ).all()

        cwe_counts = query.group_by(
            VulnerabilityCWEModel.cwe_id
        ).with_entities(
            VulnerabilityCWEModel.cwe_id,
            func.count().label('count')
        ).all()


        score_counts = query.group_by(
            CVSS3Model.exploitabilityScore
        ).with_entities(
            CVSS3Model.exploitabilityScore.label('score'),
            func.count(VulnerabilityModel.id).label('count')
        ).all()



        return ProfileCount(year=[GrapheneCount(key=year, value=count) for year, count in year_counts],
                            cwe=[GrapheneCount(key=cwe_id, value=count) for cwe_id, count in cwe_counts],
                            score=[GrapheneCount(key=score, value=count) for score, count in score_counts],
                            total=query.count())






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

    def resolve_language_extension_links_count(self, info, filter_counts: int = None):
        query = Repository.get_query(info).join(CommitModel).join(CommitFileModel)\
            .group_by(RepositoryModel.language, CommitFileModel.extension)\
            .with_entities(RepositoryModel.language, CommitFileModel.extension, sqlalchemy.func.count()).all()

        if filter_counts:
            return [Link(at=at, to=to, count=count) for at, to, count in query if count >= filter_counts]

        return [Link(at=at, to=to, count=count) for at, to, count in query]

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
