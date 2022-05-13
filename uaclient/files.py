import json
import logging
import os
from typing import Any, Dict

from uaclient import config, defaults, event_logger, schemas, util

PRIVATE_SUBDIR = "private"

event = event_logger.get_event_logger()
LOG = logging.getLogger(__name__)


class MachineTokenFile:
    def __init__(self, cfg: Dict[str, Any] = None):
        if cfg:
            self.cfg = cfg
        else:
            self.cfg_path = config.get_config_path()
            self.cfg = config.parse_config(self.cfg_path)
        self._raw_token = None
        self._file_path = None
        self._root_mode = False
        self._priv_file = defaults.PRIVATE_MACHINE_TOKEN_FILE
        self._pub_file = defaults.PUBLIC_MACHINE_TOKEN_FILE

    def read(self, root_mode=True):
        if not self._raw_token:
            try:
                self._root_mode = root_mode
                content = util.load_file(self._correct_file)
                self._root_mode = False
            except FileNotFoundError:
                if not os.path.exists(self._correct_file):
                    LOG.debug(
                        "File does not exist: {}".format(self._correct_file)
                    )
                return None
            try:
                content = content.replace("'", '"')
                self._raw_token = json.loads(
                    content, cls=util.DatetimeAwareJSONDecoder
                )
            except ValueError:
                self._raw_token = content
        return self._raw_token

    def delete(self):
        for file in self.all_files:
            if os.path.exists(file):
                os.unlink(file)
        self._raw_token = None

    def write(self, content: Any):
        self.create_files()
        self._root_mode = True
        data_dir = self.cfg.get("data_dir", "")
        filepath = os.path.join(data_dir, PRIVATE_SUBDIR, self._priv_file)
        self._raw_token = None
        if not isinstance(content, str):
            content = json.dumps(content, cls=util.DatetimeAwareJSONEncoder)
        util.write_file(filepath, content, 0o600)
        self.update_pub_file(content)

    def update_pub_file(self, content: str):
        try:
            content = json.loads(
                content
            )  # need better conversion with Line 38
        except Exception:
            return None
        schema = schemas.contract_schema
        self.filter_tokens(schema, content)
        data_dir = self.cfg.get("data_dir", "")
        pub_file = os.path.join(data_dir, self._pub_file)
        content = json.dumps(content)
        content = content.replace('"', "'")
        content = util.redact_sensitive_logs(content)
        content = content.replace("'", '"')
        util.write_file(pub_file, content, 0o644)

    def filter_tokens(self, schema, data):
        keys_to_del = []
        for k, v in data.items():
            if k not in schema:
                keys_to_del.append(k)
                LOG.debug(
                    "{key} not present in {schema}".format(
                        key=k, schema=schema
                    )
                )
            else:
                if isinstance(v, dict):
                    self.filter_tokens(schema[k], v)
                elif isinstance(v, list):
                    for i_v in v:
                        if isinstance(i_v, dict):
                            self.filter_tokens(schema[k][0], i_v)
        for k in keys_to_del:
            LOG.debug("Deleting {k} key from the data".format(k=k))
            if isinstance(data, Dict):
                del data[k]
            else:
                if k in data:
                    data.remove(k)

    @property
    def _correct_file(self):
        if not self._file_path:
            data_dir = self.cfg.get("data_dir")
            if self._root_mode:
                self._file_path = os.path.join(
                    data_dir, PRIVATE_SUBDIR, self._priv_file
                )
                self._root_mode = False
            else:
                self._file_path = os.path.join(data_dir, self._pub_file)
        return self._file_path

    @property
    def all_files(self):
        data_dir = self.cfg.get("data_dir")
        files = []
        files.append(os.path.join(data_dir, PRIVATE_SUBDIR, self._priv_file))
        files.append(os.path.join(data_dir, self._pub_file))
        return files

    def create_files(self):
        for file in self.all_files:
            data_dir = os.path.dirname(file)
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
                if os.path.basename(data_dir) == PRIVATE_SUBDIR:
                    os.chmod(data_dir, 0o700)
