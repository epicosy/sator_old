import graphene
from graphene import ObjectType
from graphql import GraphQLError
from sator.core.graphql.objects import Dataset, DatasetModel, Vulnerability, DatasetVulnerability, VulnerabilityModel,\
    DatasetVulnerabilityModel


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


class Mutation(ObjectType):
    create_dataset = CreateDataset.Field()
    remove_dataset = RemoveDataset.Field()
    remove_dataset_vulnerabilities = RemoveDatasetVulnerabilities.Field()
    add_vulnerabilities_to_dataset = AddDatasetVulnerabilities.Field()
    edit_dataset = EditDataset.Field()
