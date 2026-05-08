import json
from typing import Dict, Any, List

class AuthDiffHelper:
    @staticmethod
    def compare_json(json1: Dict[str, Any], json2: Dict[str, Any]) -> Dict[str, Any]:
        """
        Membandingkan dua JSON response untuk menemukan kebocoran data (IDOR helper).
        """
        diff = {
            "identical_keys": [],
            "different_values": {},
            "missing_in_resp2": [],
            "extra_in_resp2": []
        }

        keys1 = set(json1.keys())
        keys2 = set(json2.keys())

        # Keys yang ada di keduanya tapi beda value
        for key in keys1.intersection(keys2):
            if json1[key] == json2[key]:
                diff["identical_keys"].append(key)
            else:
                diff["different_values"][key] = {
                    "resp1": json1[key],
                    "resp2": json2[key]
                }

        diff["missing_in_resp2"] = list(keys1 - keys2)
        diff["extra_in_resp2"] = list(keys2 - keys1)

        return diff

