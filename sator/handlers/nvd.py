import json
from typing import Tuple, List

import pandas as pd

from sqlalchemy.exc import IntegrityError
from tqdm import tqdm
from pathlib import Path

from sator.core.models import Vulnerability, VulnerabilityCWE, Reference, ReferenceTag, Tag, CWE
from sator.handlers.source import SourceHandler
from sator.core.models import db


class NVDHandler(SourceHandler):
    class Meta:
        label = 'nvd'

    def __init__(self, **kw):
        super().__init__(**kw)
        self.tag_ids = {}
        self.cwe_ids = []

    def run(self):
        base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
        with self.app.flask_app.app_context():
            for tag in Tag.query.all():
                self.tag_ids[tag.name] = tag.id

            for cwe in CWE.query.all():
                self.cwe_ids.append(cwe.id)

        # download from source and extract
        for year in tqdm(range(1988, 2024, 1)):
            url = base_url.format(year=year)
            self.multi_task_handler.add(url=url, extract=True)

        self.multi_task_handler(func=self.download_file_from_url)
        results = self.multi_task_handler.results()
        del self.multi_task_handler

        # parse json files into a single dataframe
        for _, file_path in tqdm(results):
            self.multi_task_handler.add(file_path=file_path)

        self.multi_task_handler(func=self.parse)
        self.multi_task_handler.results()

        #if normalize:
        #    df = self.normalize(df, 'github')

    def parse(self, file_path: Path):
        self.app.log.info(f"Parsing {file_path}...")

        with file_path.open(mode='r') as f:
            cve_ids = json.load(f)["CVE_Items"]

            for cve in cve_ids:
                cve_id = self.get_cve(cve)

                with self.app.flask_app.app_context():
                    try:
                        # TODO: should look for existing records and update them
                        db.session.add(Vulnerability(id=cve_id, description=self.get_description(cve),
                                                     assigner=self.get_assigner(cve),
                                                     severity=self.get_severity(cve), impact=self.get_impact(cve),
                                                     exploitability=self.get_exploitability(cve),
                                                     published_date=self.get_published_date(cve),
                                                     last_modified_date=self.get_last_modified_date(cve)))

                        for cwe in self.get_cwe_ids(cve):
                            if cwe in self.cwe_ids:
                                db.session.add(VulnerabilityCWE(vulnerability_id=cve_id, cwe_id=cwe))

                        for ref in self.get_references(cve):
                            db.session.add(Reference(url=ref['url'], vulnerability_id=cve_id))

                            #for tag in ref['tags']:
                            #    db.session.add(ReferenceTag(reference_id=ref_id, tag_id=self.tag_ids[tag]))
                        db.session.commit()
                    except IntegrityError as ie:
                        self.app.log.warning(f"{ie}")

    @staticmethod
    def get_cwe_ids(cve):
        cwes = set()

        for data in cve["cve"]["problemtype"]["problemtype_data"]:
            for cwe in data["description"]:
                if cwe["value"] and cwe['value'] not in ['NVD-CWE-Other', 'NVD-CWE-noinfo']:

                    try:
                        cwe_id = int(cwe['value'].split('-')[-1])
                        cwes.add(cwe_id)
                    except ValueError:
                        continue

        return cwes

    @staticmethod
    def get_cve(data: pd.DataFrame):
        return data["cve"]["CVE_data_meta"]["ID"]

    @staticmethod
    def get_description(data):
        return data["cve"]["description"]["description_data"][0]["value"]

    @staticmethod
    def get_published_date(data):
        return data["publishedDate"]

    @staticmethod
    def get_last_modified_date(data):
        return data["lastModifiedDate"]

    @staticmethod
    def get_severity(data):
        if data["impact"]:
            if "baseMetricV2" in data["impact"].keys():
                return data["impact"]["baseMetricV2"]["severity"]
        return None

    @staticmethod
    def get_exploitability(data):
        if data["impact"]:
            if "baseMetricV2" in data["impact"].keys():
                return data["impact"]["baseMetricV2"]["exploitabilityScore"]
        return None

    @staticmethod
    def get_impact(data):
        if data["impact"]:
            if "baseMetricV2" in data["impact"].keys():
                return data["impact"]["baseMetricV2"]["impactScore"]
        return None

    @staticmethod
    def get_assigner(data):
        return data["cve"]["CVE_data_meta"]["ASSIGNER"]

    @staticmethod
    def get_references(data):
        refs = set()
        refs_list = []

        for ref in data["cve"]["references"]["reference_data"]:
            if ref['url'] not in refs:
                refs.add(ref['url'])
                refs_list.append(ref)

        return refs_list


def load(app):
    app.handler.register(NVDHandler)
