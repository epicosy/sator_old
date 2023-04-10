import hashlib
import re
import shutil
import requests
import functools
import threading

from tqdm import tqdm
from pathlib import Path
from cement import Handler
from requests import Response
from typing import Union, Tuple
from urllib.parse import urlparse

from sator.core.exc import SatorError
from sator.core.interfaces import HandlersInterface
from sator.core.models import Tag, CWE, Vulnerability, Reference, Repository, Commit, Configuration, Product, Vendor
from sator.handlers.multi_task import MultiTaskHandler


HOST_OWNER_REPO_REGEX = '(?P<host>(git@|https:\/\/)([\w\.@]+)(\/|:))(?P<owner>[\w,\-,\_]+)\/(?P<repo>[\w,\-,\_]+)(.git){0,1}((\/){0,1})'


class SourceHandler(HandlersInterface, Handler):
    class Meta:
        label = 'source'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._multi_task_handler: MultiTaskHandler = None
        self.db_ids = {}
        self.tag_ids = {}
        self.cwe_ids = []
        self.lock = threading.Lock()

    def init_global_context(self):
        self.app.log.info("Initializing global context...")
        # Setup available tags and CWE-IDs
        for tag in Tag.query.all():
            self.tag_ids[tag.name] = tag.id

        for cwe in CWE.query.all():
            self.cwe_ids.append(cwe.id)

        # Setup IDs in database
        self.app.log.info("Loading vuln IDs...")
        self.db_ids['vulns'] = set([cve.id for cve in Vulnerability.query.all()])
        self.app.log.info("Loading ref IDs...")
        self.db_ids['refs'] = set([ref.id for ref in Reference.query.all()])
        self.app.log.info("Loading repo IDs...")
        self.db_ids['repos'] = set([repo.id for repo in Repository.query.all()])
        self.app.log.info("Loading commits IDs...")
        self.db_ids['commits'] = set([commit.id for commit in Commit.query.all()])
        self.app.log.info("Loading configs IDs...")
        self.db_ids['configs'] = set([config.id for config in Configuration.query.all()])
        self.app.log.info("Loading products IDs...")
        self.db_ids['products'] = set([product.id for product in Product.query.all()])
        self.app.log.info("Loading vendors IDs...")
        self.db_ids['vendors'] = set([vendor.id for vendor in Vendor.query.all()])

    def has_id(self, _id: str, _type: str) -> bool:
        return _id in self.db_ids[_type]

    def add_id(self, _id: str, _type: str):
        with self.lock:
            self.db_ids[_type].add(_id)

    @staticmethod
    def get_digest(string: str):
        return hashlib.md5(string.encode('utf-8')).hexdigest()

    @property
    def multi_task_handler(self):
        if not self._multi_task_handler:
            self._multi_task_handler = self.app.handler.get('handlers', 'multi_task', setup=True)
        return self._multi_task_handler

    @multi_task_handler.deleter
    def multi_task_handler(self):
        self._multi_task_handler = None

    def download_file_from_url(self, url: str, extract: bool = False) -> Union[Tuple[Response, Path], None]:

        if 'http' not in url:
            self.app.lof.warning(f"URL {url} is not valid.")
            return None

        file_path = self.app.working_dir / Path(urlparse(url).path).name
        extract_file_path = self.app.working_dir / file_path.stem
        response = requests.get(url, stream=True, allow_redirects=True)

        if response.status_code != 200:
            self.app.log.error(f"Request to {url} returned status code {response.status_code}")
            return None

        total_size_in_bytes = int(response.headers.get('Content-Length', 0))

        if file_path.exists() and file_path.stat().st_size == total_size_in_bytes:
            self.app.log.warning(f"File {file_path} exists. Skipping download...")
        else:
            desc = "(Unknown total file size)" if total_size_in_bytes == 0 else ""
            response.raw.read = functools.partial(response.raw.read, decode_content=True)  # Decompress if needed

            with tqdm.wrapattr(response.raw, "read", total=total_size_in_bytes, desc=desc) as r_raw:
                with file_path.open("wb") as f:
                    shutil.copyfileobj(r_raw, f)

        if extract:
            if not extract_file_path.exists():
                self.app.log.info(f"Extracting file {extract_file_path}...")
                shutil.unpack_archive(file_path, self.app.working_dir)

            return response, extract_file_path

        return response, file_path

    @staticmethod
    def is_commit_reference(ref: str):
        match = re.search(r'(github|bitbucket|gitlab|git).*(/commit/|/commits/)', ref)

        if match:
            return match.group(1)

        return None

    @staticmethod
    def normalize_commit(ref: str) -> Union[Tuple[str, str]]:
        """
            Normalizes commit reference
            returns tuple containing clean_commit, sha
        """

        if "CONFIRM:" in ref:
            # e.g., https://github.com/{owner}/{repo}/commit/{sha}CONFIRM:
            ref = ref.replace("CONFIRM:", '')

        match_sha = re.search(r"\b[0-9a-f]{5,40}\b", ref)

        if not match_sha:
            # e.g., https://github.com/intelliants/subrion/commits/develop
            # e.g., https://gitlab.gnome.org/GNOME/gthumb/commits/master/extensions/cairo_io/cairo-image-surface-jpeg.c
            # e.g., https://github.com/{owner}/{repo}/commits/{branch}
            raise SatorError(f"Could not normalize commit")

        if 'git://' in ref and 'github.com' in ref:
            ref = ref.replace('git://', 'https://')

        if '/master?' in ref:
            # e.g., https://github.com/{owner}/{repo}/commits/master?after={sha}+{no_commits}
            raise SatorError(f"Could not normalize commit")

        if '#' in ref and ('#comments' in ref or '#commitcomment' in ref):
            # e.g., https://github.com/{owner}/{repo}/commit/{sha}#commitcomment-{id}
            ref = ref.split('#')[0]

        if '.patch' in ref:
            # e.g., https://github.com/{owner}/{repo}/commit/{sha}.patch
            ref = ref.replace('.patch', '')
        if '%23' in ref:
            # e.g., https://github.com/absolunet/kafe/commit/c644c798bfcdc1b0bbb1f0ca59e2e2664ff3fdd0%23diff
            # -f0f4b5b19ad46588ae9d7dc1889f681252b0698a4ead3a77b7c7d127ee657857
            ref = ref.replace('%23', '#')

            # FIXME: github links to diffs are not considered for now; looking into a solution for it
            if "#diff" not in ref:
                ref = ref.split("#")[0]

        if "?w=1" in ref:
            ref = ref.replace("?w=1", "")
        if "?branch=" in ref:
            ref = ref.split("?branch=")[0]
        if "?diff=split" in ref:
            ref = ref.replace("?diff=split", "")
        if re.match(r".*(,|/)$", ref):
            if "/" in ref:
                ref = ref[0:-1]
            else:
                ref = ref.replace(",", "")
        elif ")" in ref:
            ref = ref.replace(")", "")

        return ref, match_sha.group(0)

    @staticmethod
    def extract_owner_repo(commit_url: str):
        match = re.search(HOST_OWNER_REPO_REGEX, commit_url)

        if match:
            return match['owner'], match['repo']

        raise SatorError(f"Could not extract owner/repo from commit url")
