import xml.etree.ElementTree as ET
from pydantic import BaseModel
from typing import List, Optional, Dict
from enum import Enum

from product_cybersecurity.utils.parsingutils import extract_description_with_html


class CweAbstractionEnum(str, Enum):
    PILLAR = "Pillar"
    CLASS = "Class"
    BASE = "Base"
    VARIANT = "Variant"
    COMPOUND = "Compound"

class CweDetectionMethodsEnum(str, Enum):
    AUTOMATED_ANALYSIS = "Automated Analysis"
    AUTOMATED_DYNAMIC_ANALYSIS = "Automated Dynamic Analysis"
    AUTOMATED_STATIC_ANALYSIS = "Automated Static Analysis"
    AUTOMATED_STATIC_ANALYSIS_SOURCE_CODE = "Automated Static Analysis - Source Code"
    AUTOMATED_STATIC_ANALYSIS_BINARY_OR_BYTECODE = "Automated Static Analysis - Binary or Bytecode"
    FUZZING = "Fuzzing"
    MANUAL_ANALYSIS = "Manual Analysis"
    MANUAL_DYNAMIC_ANALYSIS = "Manual Dynamic Analysis"
    MANUAL_STATIC_ANALYSIS = "Manual Static Analysis"
    MANUAL_STATIC_ANALYSIS_SOURCE_CODE = "Manual Static Analysis - Source Code"
    MANUAL_STATIC_ANALYSIS_BINARY_OR_BYTECODE = "Manual Static Analysis - Binary or Bytecode"
    WHITE_BOX = "White Box"
    BLACK_BOX = "Black Box"
    ARCHITECTURE_OR_DESIGN_REVIEW = "Architecture or Design Review"
    DYNAMIC_ANALYSIS_WITH_MANUAL_RESULTS_INTERPRETATION = "Dynamic Analysis with Manual Results Interpretation"
    DYNAMIC_ANALYSIS_WITH_AUTOMATED_RESULTS_INTERPRETATION = "Dynamic Analysis with Automated Results Interpretation"
    FORMAL_VERIFICATION = "Formal Verification"
    SIMULATION_EMULATION = "Simulation / Emulation"
    OTHER = "Other"

class DetectionEffectivenessEnum(str, Enum):
    HIGH = "High"
    MODERATE = "Moderate"
    SOAR_PARTIAL = "SOAR Partial"  # According to the IATAC State Of the Art Report (SOAR), this indicates partial effectiveness of the detection method.
    OPPORTUNISTIC = "Opportunistic"
    LIMITED = "Limited"
    NONE = "None"

class EffectivenessEnum(str, Enum):
    HIGH = "High"
    MODERATE = "Moderate"
    LIMITED = "Limited"
    INCIDENTAL = "Incidental"
    DISCOURAGED_COMMON_PRACTICE = "Discouraged Common Practice"
    DEFENSE_IN_DEPTH = "Defense in Depth"
    NONE = "None"

class RelatedCweNatureEnum(str, Enum):
    CHILD_OF = "ChildOf"
    PARENT_OF = "ParentOf"
    STARTS_WITH = "StartsWith"
    CAN_FOLLOW = "CanFollow"
    CAN_PRECEDE = "CanPrecede"
    REQUIRED_BY = "RequiredBy"
    REQUIRES = "Requires"
    CAN_ALSO_BE = "CanAlsoBe"
    PEER_OF = "PeerOf"


class CweStatusEnum(str, Enum):
    DEPRECATED = "Deprecated"
    DRAFT = "Draft"
    INCOMPLETE = "Incomplete"
    OBSOLETE = "Obsolete"
    STABLE = "Stable"
    USABLE = "Usable"

class RelatedCWE(BaseModel):
    CWE_ID: str
    Nature: RelatedCweNatureEnum

class Cwe(BaseModel):
    """
    CAPEC Attack Pattern
    """
    ID: str
    Name: str
    Number: int
    Abstraction: CweAbstractionEnum
    Status: CweStatusEnum
    Description: str
    Extended_Description: Optional[str]
    # Likelihood_Of_Attack: Optional[str]
    # Typical_Severity: Optional[str]
    Related_CWEs: Optional[List[RelatedCWE]]
    # Prerequisites: Optional[List[str]]
    # Skills_Required: Optional[List[SkillRequired]]
    # Resources_Required: Optional[List[str]]
    # Mitigations: Optional[List[str]]
    # Related_Weaknesses: Optional[List[str]]
    # Execution_Flow: Optional[List[dict]]  # TODO define a more detailed model for Execution Flow if needed


class CweCollection(BaseModel):
    CWEs : Dict[str, Cwe]


def parse_cwe_xml(xml_content) -> CweCollection:
    # Parse the XML content
    root = ET.fromstring(xml_content)
    # print(root)
    # Define namespaces
    ns = {
        'cwe': 'http://cwe.mitre.org/cwe-7',
        'xhtml': 'http://www.w3.org/1999/xhtml'
    }

    cwe_dict = {}  # Dictionary to hold all attack patterns
    desc_count = []
    for cwe in root.findall(".//cwe:Weakness", ns):
        # Process Description
        description_element = cwe.find(".//cwe:Description", ns)
        description_text = extract_description_with_html(description_element, ns)

        # Process Extended Description
        extended_description_element = cwe.find(".//cwe:Extended_Description", ns)
        extended_description_text = extract_description_with_html(extended_description_element, ns)

        # Initialize attack details dictionary
        cwe_details = {
            "ID": "CWE-" + cwe.get("ID"),
            "Number": cwe.get("ID"),
            "Name": cwe.get("Name"),
            "Status": cwe.get("Status"),
            "Abstraction": cwe.get("Abstraction"),
            "Description": description_text,
            "Extended_Description" : extended_description_text,
        }


        # Process Related Attack Patterns
        related_CWEs = []
        for related in cwe.findall(".//cwe:Related_Weaknesses/cwe:Related_Weakness", ns):
            related_c = RelatedCWE(CWE_ID="CWE-" + related.get("CWE_ID"), Nature=related.get("Nature"))
            related_CWEs.append(related_c)
        if related_CWEs:
            cwe_details["Related_CWEs"] = related_CWEs
        else:
            cwe_details["Related_CWEs"] = None
        
        # add the details into the cwe_dict
        cwe_dict[cwe_details["ID"]] = cwe_details
    cwecol = CweCollection(CWEs=cwe_dict)

    return cwecol
