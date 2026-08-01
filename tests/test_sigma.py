from pathlib import Path

from blackterm_mitre_mapper.engine import MitreMapper
from blackterm_mitre_mapper.sigma import convert_sigma_file

SAMPLE = Path(__file__).parents[1] / 'examples' / 'custom_rules' / 'sigma_encoded_powershell.yml'


def test_sigma_conversion_and_detection():
    rules = convert_sigma_file(SAMPLE)
    assert rules[0].technique_id == 'T1059.001'
    result = MitreMapper(rules).analyze_event({
        'process': {
            'name': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'command_line': 'powershell.exe -enc SQBFAFgA',
        }
    })
    assert result.mappings[0].technique_id == 'T1059.001'
