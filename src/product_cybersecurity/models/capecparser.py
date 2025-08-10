import xml.etree.ElementTree as ET
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum
from product_cybersecurity.utils.parsingutils import extract_description_with_html

class RelatedAttackPatternNatureEnum(str, Enum):
    CHILD_OF = "ChildOf"
    PARENT_OF = "ParentOF"
    CAN_FOLLOW = "CanFollow"
    CAN_PRECEDE = "CanPrecede"
    CAN_ALSO_BE = "CanAlsoBe"
    PEER_OF = "PeerOf"

class CapecAbstractionEnum(str, Enum):
    META = "Meta"
    STANDARD = "Standard"
    DETAILED = "Detailed"

# Define Pydantic models
class RelatedAttackPattern(BaseModel):
    CAPEC_ID: str
    Nature: RelatedAttackPatternNatureEnum

class SkillLevelEnum(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"

class AttackStepEnum(str, Enum):
    EXPLORE = "Explore"
    EXPERIMENT = "Experiment"
    EXPLOIT = "Exploit"

class SkillRequired(BaseModel):
    """
    Details the skill level required for an attack pattern, along with a description.
    """
    Level: Optional[SkillLevelEnum]
    Description: Optional[str]

class CapecStatusEnum(str, Enum):
    DEPRECATED = "Deprecated"
    DRAFT = "Draft"
    INCOMPLETE = "Incomplete"
    OBSOLETE = "Obsolete"
    STABLE = "Stable"
    USABLE = "Usable"


class AttackPattern(BaseModel):
    """
    CAPEC Attack Pattern
    """
    ID: str
    Name: str
    Number: str
    Abstraction: CapecAbstractionEnum
    Status: CapecStatusEnum
    Description: str
    Extended_Description: str
    Likelihood_Of_Attack: Optional[str]
    Typical_Severity: Optional[str]
    Related_Attack_Patterns: Optional[List[RelatedAttackPattern]]
    Prerequisites: Optional[List[str]]
    Skills_Required: Optional[List[SkillRequired]]
    Resources_Required: Optional[List[str]]
    Mitigations: Optional[List[str]]
    Related_Weaknesses: Optional[List[str]]
    Execution_Flow: Optional[List[Dict[str, Any]]]

class CapecCollection(BaseModel):
    Capecs : Dict[str, AttackPattern]



# New function to parse CAPEC XML and return Pydantic object
def parse_capec_xml_pydantic(xml_content : str) -> CapecCollection:
    root = ET.fromstring(xml_content)
    ns = {'capec': 'http://capec.mitre.org/capec-3', 'xhtml': 'http://www.w3.org/1999/xhtml'}

    attack_patterns: Dict[str, AttackPattern] = {}
    for attack_pattern in root.findall(".//capec:Attack_Pattern", ns):

# Process Description
        description_element = attack_pattern.find(".//capec:Description", ns)
        description_text = extract_description_with_html(description_element, ns)

        extended_description_element = attack_pattern.find(".//capec:Extended_Description", ns)
        extended_description_text = extract_description_with_html(extended_description_element, ns)

        # Initialize attack details dictionary
        attack_details: Dict[str, Any] = {
            "ID": "CAPEC-" + str(attack_pattern.get("ID")),
            "Number": str(attack_pattern.get("ID")),
            "Name": str(attack_pattern.get("Name")),
            "Status": CapecStatusEnum(attack_pattern.get("Status")),
            "Abstraction": CapecAbstractionEnum(attack_pattern.get("Abstraction")),
            "Description": description_text,
            "Extended_Description" : extended_description_text,
            "Likelihood_Of_Attack": attack_pattern.findtext("capec:Likelihood_Of_Attack", namespaces=ns),
            "Typical_Severity": attack_pattern.findtext("capec:Typical_Severity", namespaces=ns),
        }

        # Process Related Attack Patterns
        related_attack_patterns: List[Dict[str, str]] = []
        for related in attack_pattern.findall(".//capec:Related_Attack_Pattern", ns):
            related_attack_patterns.append({
                "CAPEC_ID": "CAPEC-" + str(related.get("CAPEC_ID")),
                "Nature": str(related.get("Nature"))
            })
        if related_attack_patterns:
            attack_details["Related_Attack_Patterns"] = related_attack_patterns

        # Process Prerequisites
        prerequisites: List[str] = []
        for prereq in attack_pattern.findall(".//capec:Prerequisites/capec:Prerequisite", ns):
            if prereq.text is not None:
                prerequisites.append(prereq.text)
        if prerequisites:
            attack_details["Prerequisites"] = prerequisites

        # Process Skills Required
        skills_required: List[Dict[str, Optional[str]]] = []
        for skill in attack_pattern.findall(".//capec:Skills_Required/capec:Skill", ns):
            skill_detail = {
                "Level": skill.get("Level"),
                "Description": skill.text
            }
            skills_required.append(skill_detail)
        if skills_required:
            attack_details["Skills_Required"] = skills_required

        # Process Resources_Required
        resources_required: List[str] = []
        for resource in attack_pattern.findall(".//capec:Resources_Required/capec:Resource", ns):
            aaa = extract_description_with_html(resource, ns)
            resources_required.append(aaa)
        if resources_required:
            attack_details["Resources_Required"] = resources_required

        # Process Mitigations
        mitigations: List[str] = []
        for mitig in attack_pattern.findall(".//capec:Mitigations/capec:Mitigation", ns):
            if mitig.text is not None:
                mitigations.append(mitig.text)
        if mitigations:
            attack_details["Mitigations"] = mitigations

        # Process Related Weaknesses
        weaknesses: List[str] = []
        for weakness in attack_pattern.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", ns):
            cwe_id = weakness.get("CWE_ID")
            if cwe_id is not None:
                weaknesses.append("CWE-" + str(cwe_id))
        if weaknesses:
            attack_details["Related_Weaknesses"] = weaknesses

        # Extract Execution Flow
        execution_flow: List[Dict[str, Any]] = []
        for step in attack_pattern.findall(".//capec:Execution_Flow/capec:Attack_Step", ns):
            description_element = step.find('capec:Description', ns)
            description_text = extract_description_with_html(description_element, ns)

            step_tag = step.find('capec:Step', ns)
            phase_tag = step.find('capec:Phase', ns)
            step_data = {
                'Step': step_tag.text if step_tag is not None else None,
                'Phase': phase_tag.text if phase_tag is not None else None,
                'Description': description_text,
                'Techniques': [tech.text for tech in step.findall('capec:Technique', ns) if tech.text is not None]
            }
            execution_flow.append(step_data)

        # Add Execution Flow to attack details
        if execution_flow:
            attack_details['Execution_Flow'] = execution_flow

        # Create an instance of the AttackPattern model
        attack_pattern_model = AttackPattern(
            ID=attack_details["ID"],
            Name=attack_details["Name"],
            Number=attack_details["Number"],
            Status=attack_details["Status"],
            Abstraction=attack_details["Abstraction"],
            Description=attack_details["Description"],
            Extended_Description=attack_details["Extended_Description"],
            Likelihood_Of_Attack=attack_details.get("Likelihood_Of_Attack"),
            Typical_Severity=attack_details.get("Typical_Severity"),
            Related_Attack_Patterns=[RelatedAttackPattern(**rap) for rap in related_attack_patterns] if related_attack_patterns else None,
            Prerequisites=prerequisites or None,
            Skills_Required=[SkillRequired(**skill) for skill in skills_required] if skills_required else None,
            Resources_Required=resources_required or None,
            Mitigations=mitigations or None,
            Related_Weaknesses=weaknesses or None,
            Execution_Flow=execution_flow or None
        )

        attack_patterns[attack_pattern_model.ID] = attack_pattern_model
    
    capecs = CapecCollection(Capecs=attack_patterns)
    
    return capecs

