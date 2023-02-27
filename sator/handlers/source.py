import shutil
import requests
import functools

from tqdm import tqdm
from pathlib import Path
from cement import Handler
from requests import Response
from typing import Union, Tuple
from urllib.parse import urlparse

from sator.core.exc import SatorError
from sator.core.interfaces import HandlersInterface
from sator.handlers.multi_task import MultiTaskHandler


class SourceHandler(HandlersInterface, Handler):
    class Meta:
        label = 'source'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._multi_task_handler: MultiTaskHandler = None

    @property
    def multi_task_handler(self):
        if not self._multi_task_handler:
            self._multi_task_handler = self.app.handler.get('handlers', 'multi_task', setup=True)
        return self._multi_task_handler

    @multi_task_handler.deleter
    def multi_task_handler(self):
        self._multi_task_handler = None

    '''
    def normalize(self, df: pd.DataFrame, code_source: str):
        # normalize refs
        df['refs'] = df['refs'].apply(lambda ref: split_commits(ref))
        # drop cases with no refs
        df = df.dropna(subset=['refs'])
        self.app.log.info(f"Size after null refs drop: {len(df)}")
        df = filter_references(df)
        self.app.log.info(f"Size after filtering refs: {len(df)}")
        df = normalize_commits(df)
        self.app.log.info(f"Size after normalizing refs: {len(df)}")

        if code_source:
            df = filter_commits_by_source(df, source=code_source)

        return df
    '''

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
