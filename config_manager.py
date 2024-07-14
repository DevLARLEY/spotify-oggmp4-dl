import json
import logging
from os.path import exists


class ConfigManager:
    def __init__(self):
        self.config_file_name = "config.json"
        self.defaults = {
            "sp_dc": None,
            "accessToken": None,
            "accessTokenExpire": -1
        }
        self.config = self.defaults

    def initialize(self):
        if not exists(self.config_file_name):
            js = json.dumps(self.config)
            with open(self.config_file_name, "w") as io_writer:
                io_writer.write(js)

    def read_config(self) -> bool:
        with open(self.config_file_name, "r") as io_reader:
            js = io_reader.read()
        try:
            jo = json.loads(js)
        except Exception as ex:
            logging.error(f"Unable to parse json config file: {ex}")
            return False
        for key in self.config.keys():
            if key not in jo:
                logging.error(f"Unable to locate key '{key}'in config file")
                continue
            self.config[key] = jo[key]

    def get(self, key: str):
        if key in self.config:
            return self.config[key]
        else:
            logging.error(f"Key '{key}' is not a valid config key")

    def simple_get(self, key: str):
        self.read_config()
        return self.get(key)

    def get_default(self, key: str):
        if key in self.defaults:
            return self.defaults[key]
        else:
            logging.error(f"Key '{key}' is not a valid default config key")

    def write_config(self):
        js = json.dumps(self.config)
        with open(self.config_file_name, "w") as io_writer:
            io_writer.write(js)

    def set(self, key: str, value):
        if key in self.config:
            self.config[key] = value
        else:
            logging.error(f"Key '{key}' is not a valid config key")

    def simple_set(self, key: str, value):
        self.set(key, value)
        self.write_config()


cM = ConfigManager()
cM.initialize()
