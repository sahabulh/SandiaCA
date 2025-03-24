import json
from dataclasses import dataclass
from typing import Optional

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent)

def get_config(config_path):
    try:
        with open(abs_path+"/"+config_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File not found: {config_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in {config_path}")
        return None

@dataclass
class Config:
    country_code: Optional[str] = None
    organization_name: str = "Sandia National Labs"
    organizational_unit_name: Optional[str] = None
    state_or_province_name: Optional[str] = None

    def load(self, config_path: str = "config.json"):
        config = get_config(config_path)
        try:
            self = Config(**config)
        except:
            print("Error occured while loading configuration. Defaults will be used.")
        finally:
            return self