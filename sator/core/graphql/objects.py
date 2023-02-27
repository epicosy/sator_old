import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType
from sator.core.models import CWE as CWEModel, Abstraction as AbstractionModel, Operation as OperationModel, \
    Phase as PhaseModel, BFClass as BFClassModel, CWEOperation as CWEOperationModel, CWEPhase as CWEPhaseModel, \
    CWEBFClass as CWEBFClassModel, Vulnerability as VulnerabilityModel, VulnerabilityCWE as VulnerabilityCWEModel, \
    Reference as ReferenceModel


class Reference(SQLAlchemyObjectType):
    class Meta:
        model = ReferenceModel
        use_connection = True


class Abstraction(SQLAlchemyObjectType):
    class Meta:
        model = AbstractionModel
        use_connection = True

    name = graphene.String()


class Operation(SQLAlchemyObjectType):
    class Meta:
        model = OperationModel
        use_connection = True


class CWEOperation(SQLAlchemyObjectType):
    class Meta:
        model = CWEOperationModel
        use_connection = True


class Phase(SQLAlchemyObjectType):
    class Meta:
        model = PhaseModel
        use_connection = True


class CWEPhase(SQLAlchemyObjectType):
    class Meta:
        model = CWEPhaseModel
        use_connection = True


class BFClass(SQLAlchemyObjectType):
    class Meta:
        model = BFClassModel
        use_connection = True


class CWEBFClass(SQLAlchemyObjectType):
    class Meta:
        model = CWEBFClassModel
        use_connection = True


class VulnerabilityCWE(SQLAlchemyObjectType):
    class Meta:
        model = VulnerabilityCWEModel
        use_connection = True


class Vulnerability(SQLAlchemyObjectType):
    class Meta:
        model = VulnerabilityModel
        use_connection = True

    cwe_ids = graphene.List(lambda: CWE)
    references = graphene.List(lambda: Reference)

    def resolve_references(self, info):
        references_query = Reference.get_query(info=info)
        cwe_vuln_query = references_query.filter(ReferenceModel.vulnerability_id == self.id)

        return cwe_vuln_query.all()

    def resolve_cwe_ids(self, info):
        cwe_vuln_query = VulnerabilityCWE.get_query(info=info)
        cwe_vuln_query = cwe_vuln_query.filter(VulnerabilityCWEModel.vulnerability_id == self.id)

        cwes = []
        cwes_query = CWE.get_query(info=info)

        for cwe_vuln in cwe_vuln_query.all():
            cwe = cwes_query.filter(CWEModel.id == cwe_vuln.cwe_id)

            if cwe.first():
                cwes.append(cwe.first())

        return cwes


class CWE(SQLAlchemyObjectType):
    class Meta:
        model = CWEModel
        use_connection = True
        filter_fields = ["id"]

    abstraction = graphene.String()
    operations = graphene.List(lambda: Operation, name=graphene.String())
    phases = graphene.List(lambda: Phase, name=graphene.String(), acronym=graphene.String())
    bf_classes = graphene.List(lambda: BFClass, name=graphene.String())

    def resolve_id(self, info):
        return self.id

    def resolve_abstraction(self, info):
        query = Abstraction.get_query(info=info)
        query = query.filter(AbstractionModel.id == self.abstraction_id)

        return query.first().name

    def resolve_operations(self, info, name=None):
        cwe_op_query = CWEOperation.get_query(info=info)
        cwe_op_query = cwe_op_query.filter(CWEOperationModel.cwe_id == self.id)

        ops = []
        ops_query = Operation.get_query(info=info)

        for cwe_op in cwe_op_query.all():
            ops_query = ops_query.filter(OperationModel.id == cwe_op.operation_id)

            if name:
                ops_query = ops_query.filter(OperationModel.name == name)

            if ops_query.first():
                ops.append(ops_query.first())

        return ops

    def resolve_phases(self, info, name=None, acronym=None):
        phases = []
        cwe_phase_query = CWEPhase.get_query(info=info)
        cwe_phase_query = cwe_phase_query.filter(CWEPhaseModel.cwe_id == self.id)
        phases_query = Phase.get_query(info=info)

        for cwe_phase in cwe_phase_query.all():
            phases_query = phases_query.filter(PhaseModel.id == cwe_phase.phase_id)

            if name:
                phases_query = phases_query.filter(PhaseModel.name == name)
            if acronym:
                phases_query = phases_query.filter(PhaseModel.acronym == acronym)

            if phases_query.first():
                phases.append(phases_query.first())

        return phases

    def resolve_bf_class(self, info, name=None):
        bf_classes = []
        cwe_bf_class_query = CWEBFClass.get_query(info=info)
        cwe_bf_class_query = cwe_bf_class_query.filter(CWEBFClassModel.cwe_id == self.id)
        bf_classes_query = BFClass.get_query(info=info)

        for cwe_bf_class in cwe_bf_class_query.all():
            bf_classes_query = bf_classes_query.filter(BFClassModel.id == cwe_bf_class.bf_class_id)

            if name:
                bf_classes_query = bf_classes_query.filter(PhaseModel.name == name)

            if bf_classes_query.first():
                bf_classes.append(bf_classes_query.first())

        return bf_classes
