import graphene

from graphene import ObjectType
from graphql import GraphQLError
from sator.core.graphql.objects import Dataset, DatasetModel, Vulnerability, DatasetVulnerability, VulnerabilityModel, \
    DatasetVulnerabilityModel, CommitFile, LineModel, Line, Repository, ProductType, RepositoryProductType, \
    RepositoryProductTypeModel, Function, FunctionModel
from sator.utils.misc import get_file_content_from_url, get_digest, JavaMethodExtractor


class CreateDataset(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        description = graphene.String(required=False)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, name, description=None):

        if Dataset.get_query(info).filter_by(name=name).first():
            raise GraphQLError(f"Dataset with name {name} already exists")

        dataset = DatasetModel(name=name, description=description)
        dataset.save()

        dataset = Dataset(id=dataset.id, name=name, description=description)

        return CreateDataset(dataset=dataset)


class EditDataset(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)
        name = graphene.String(required=False)
        description = graphene.String(required=False)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int, name: str, description: str):
        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        if name and name != dataset.name:
            # check if name does not exist in the dataset table
            if Dataset.get_query(info).filter_by(name=name).first():
                raise GraphQLError(f"Dataset with name {name} already exists")

            # check the length of the dataset name is not more than 255 characters
            if len(name) > 255:
                raise GraphQLError(f"Dataset name cannot be more than 255 characters")

            dataset.name = name

        if description:
            # check if the length of the description is not more than 1000 characters
            if len(description) > 1000:
                raise GraphQLError(f"Dataset description cannot be more than 1000 characters")

            dataset.description = description

        dataset.save()

        return EditDataset(dataset=dataset)


class RemoveDataset(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int):

        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        # remove all dataset vulnerabilities
        dataset_vulnerabilities = DatasetVulnerability.get_query(info).filter_by(dataset_id=id).all()

        for dv in dataset_vulnerabilities:
            dv.remove()

        # remove dataset
        dataset.remove()

        return RemoveDataset(dataset=dataset)


class RemoveDatasetVulnerabilities(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int):
        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        dataset_vulnerabilities = DatasetVulnerability.get_query(info).filter_by(dataset_id=id).all()

        for dv in dataset_vulnerabilities:
            dv.remove()

        return RemoveDatasetVulnerabilities(dataset=dataset)


class AddDatasetVulnerabilities(graphene.Mutation):
    class Arguments:
        vulnerability_ids = graphene.List(graphene.String, required=True)
        dataset_id = graphene.Int(required=True)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, vulnerability_ids: list, dataset_id: int):
        if not vulnerability_ids:
            raise GraphQLError("No vulnerabilities provided")

        if not dataset_id:
            raise GraphQLError("No dataset id provided")

        dataset = Dataset.get_query(info).filter_by(id=dataset_id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {dataset_id} does not exist")

        dataset_vulnerabilities = DatasetVulnerability.get_query(info).filter_by(dataset_id=dataset_id).all()
        dataset_vulnerability_ids = [dv.vulnerability_id for dv in dataset_vulnerabilities]

        # the following checks if vulnerabilities exist in the vulnerability table
        vulns = Vulnerability.get_query(info).filter(VulnerabilityModel.id.in_(vulnerability_ids)).all()

        for vuln in vulns:
            if vuln.id not in dataset_vulnerability_ids:
                dv = DatasetVulnerabilityModel(dataset_id=dataset_id, vulnerability_id=vuln.id)
                dv.save()

        # return error message for the rest of vulnerabilities that were not added to the dataset
        if len(vulnerability_ids) != len(vulns):
            vuln_ids = [v.id for v in vulns]
            for v in vulnerability_ids:
                if v not in vuln_ids:
                    raise GraphQLError(f"Vulnerability with id {v} does not exist")

        return AddDatasetVulnerabilities(dataset=dataset)


class LoadFile(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)

    file = graphene.Field(lambda: CommitFile)

    def mutate(self, info, id: str):
        file = CommitFile.get_query(info).filter_by(id=id).first()

        if not file:
            raise GraphQLError(f"File with id {id} does not exist")

        try:
            content = get_file_content_from_url(file.raw_url)
        except Exception as e:
            raise GraphQLError(f"Error loading file content from url {file.raw_url}: {e}")

        lines = Line.get_query(info).filter_by(commit_file_id=file.id).all()

        if not lines:
            line_records = []

            for i, line in enumerate(content.split("\n"), 1):
                line_id = get_digest(f"{file.id}-{i}")
                line_records.append(LineModel(id=line_id, number=i, content=line, commit_file_id=file.id))

            LineModel.add_all(line_records)

        return LoadFile(file=file)


class ExtractFunctions(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)

    file = graphene.Field(lambda: CommitFile)

    def mutate(self, info, id: str):
        file = CommitFile.get_query(info).filter_by(id=id).first()

        if not file:
            raise GraphQLError(f"File with id {id} does not exist")

        if file.extension != ".java":
            raise GraphQLError(f"File with id {id} is not within available languages: [Java]")

        functions = Function.get_query(info).filter_by(commit_file_id=file.id).order_by(FunctionModel.start).all()

        if not functions:

            lines = Line.get_query(info).filter_by(commit_file_id=file.id).all()

            if not lines:
                raise GraphQLError(f"File with id {id} has not been previously loaded")

            try:
                jve = JavaMethodExtractor(code_lines=[l.content for l in lines])
            except Exception as e:
                raise GraphQLError(f"Failed to extract methods: {str(e)}")

            for method in jve.methods:
                functions.append(FunctionModel(id=get_digest(f"{file.id}-{method.name}-{method.start_line}"),
                                               name=method.name, start_line=method.start_line, start_col=method.start_col,
                                               end_line=method.end_line, end_col=method.end_col, commit_file_id=file.id,
                                               size=len(method))
                                 )

            FunctionModel.add_all(functions)

        return ExtractFunctions(file=file)


class RepositorySoftwareType(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)
        software_type_id = graphene.Int(required=True)

    repository = graphene.Field(lambda: Repository)

    def mutate(self, info, id: str, software_type_id: int):
        repository = Repository.get_query(info).filter_by(id=id).first()

        if not repository:
            raise GraphQLError(f"Repository with id {id} does not exist")

        software_type = ProductType.get_query(info).filter_by(id=software_type_id).first()

        if not software_type:
            raise GraphQLError(f"Software type with id {software_type_id} does not exist")

        repository_product_type = RepositoryProductType.get_query(info).filter_by(repository_id=id).first()

        if repository_product_type:
            repository_product_type.product_type_id = software_type_id
        else:
            repository_product_type = RepositoryProductTypeModel(repository_id=id, product_type_id=software_type_id)

        repository_product_type.save()
        repository.software_type = software_type.name

        return RepositorySoftwareType(repository=repository)


class Mutation(ObjectType):
    create_dataset = CreateDataset.Field()
    remove_dataset = RemoveDataset.Field()
    remove_dataset_vulnerabilities = RemoveDatasetVulnerabilities.Field()
    add_vulnerabilities_to_dataset = AddDatasetVulnerabilities.Field()
    edit_dataset = EditDataset.Field()
    load_file = LoadFile.Field()
    repository_software_type = RepositorySoftwareType.Field()


