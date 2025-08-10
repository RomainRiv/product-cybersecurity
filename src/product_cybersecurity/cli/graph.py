from product_cybersecurity.models.capecparser import  AttackPattern, CapecCollection, RelatedAttackPatternNatureEnum, CapecAbstractionEnum
from product_cybersecurity.models.cweparser import Cwe, CweCollection, RelatedCweNatureEnum, CweAbstractionEnum
import networkx as nx
from networkx.readwrite import json_graph
from enum import Enum
from typing import List
import json
import argparse
import os

class LabelClassEnum(str, Enum):
    BIG = "node-label-big"
    MEDIUM = "node-label-medium"
    SMALL = "node-label-small"
    ERROR= "error"

class SecurityDataEnum(str, Enum):
    CWE = "CWE"
    CAPEC = "CAPEC"


def save_graph_json(graph: nx.Graph, file_path: str):
    graph_json = json_graph.node_link_data(graph)

    with open(file_path, "w") as f:
        json.dump(graph_json, f, indent=2)

def capec_graph(capec_collection: CapecCollection) -> nx.DiGraph:
    G_capec: nx.DiGraph = nx.DiGraph()
    for capec in capec_collection.Capecs.values():
        G_capec.add_node(capec.ID)
        if (capec.Related_Attack_Patterns):
            for related_ap in capec.Related_Attack_Patterns:
                if (related_ap.Nature == RelatedAttackPatternNatureEnum.CHILD_OF):
                    G_capec.add_edge(capec.ID, related_ap.CAPEC_ID)


    for node in G_capec.nodes:
        G_capec.nodes[node]["Description"] = f"<b>{capec_collection.Capecs[node].ID}: {capec_collection.Capecs[node].Name}</b><br>{capec_collection.Capecs[node].Description}"
        match capec_collection.Capecs[node].Abstraction:
            case CapecAbstractionEnum.META:
                color = "#2176ff"
                size = 30
                label_class = LabelClassEnum.BIG 
            case CapecAbstractionEnum.STANDARD:
                color = "#75aaff"
                size = 18
                label_class = LabelClassEnum.MEDIUM
            case CapecAbstractionEnum.DETAILED:
                color = "#94ebff"
                size = 10
                label_class = LabelClassEnum.SMALL
            case _:
                size = 10
                color = "#ff0000"
                label_class= LabelClassEnum.SMALL

        G_capec.nodes[node]["color"] = color
        G_capec.nodes[node]["size"] = size
        G_capec.nodes[node]["label"] = capec_collection.Capecs[node].Name
        G_capec.nodes[node]["label_class"] = label_class
        G_capec.nodes[node]["type"] = SecurityDataEnum.CAPEC
        G_capec.nodes[node]["abstraction"] = capec_collection.Capecs[node].Abstraction
        G_capec.nodes[node]["url"] = f"https://capec.mitre.org/data/definitions/{capec_collection.Capecs[node].Number}.html"
    
    return G_capec

def save_capec_subgraphs(capec_graph: nx.DiGraph, capec_collection: CapecCollection, output_dir: str) -> None:
    meta_capec = []
    for capec_k, capec in capec_collection.Capecs.items():
        if capec.Abstraction == CapecAbstractionEnum.META:
            meta_capec.append(capec)
            G_undirected = capec_graph.to_undirected()
            nodes_bfs = list(nx.bfs_tree(G_undirected, capec.ID))
            capec_subgraph = capec_graph.subgraph(nodes_bfs)
            save_graph_json(capec_subgraph, os.path.join(output_dir, f"{capec.ID}.json"))

def save_capec_md(capec_collection: CapecCollection, md_filepath: str) -> None:
    meta_capec : List[AttackPattern] = []

    for capec in capec_collection.Capecs.values():
        if capec.Abstraction == CapecAbstractionEnum.META:
            meta_capec.append(capec)
    
    sorted_metacapec = sorted(meta_capec, key=lambda x: x.Name)
    md = []

    md.append("## List of Meta CAPECs")
    for c in sorted_metacapec:
        md.append(f"- [{c.ID} {c.Name}](../visualizer.html?jsonfile={c.ID}.json)")

    with open(md_filepath, "w") as f:
        f.write('\n'.join(md))
    

def cwe_graph(cwe_collection : CweCollection)-> nx.DiGraph:
    G_cwe: nx.DiGraph = nx.DiGraph()

    for cwe in cwe_collection.CWEs.values():
        G_cwe.add_node(cwe.ID)
        if (cwe.Related_CWEs):
            for related_cwe in cwe.Related_CWEs:
                if (related_cwe.Nature == RelatedCweNatureEnum.CHILD_OF):
                    G_cwe.add_edge(cwe.ID, related_cwe.CWE_ID)


    for node in G_cwe.nodes:
        G_cwe.nodes[node]["Description"] = f"<b>{cwe_collection.CWEs[node].ID}: {cwe_collection.CWEs[node].Name}</b><br>{cwe_collection.CWEs[node].Description}"
        match cwe_collection.CWEs[node].Abstraction:
            case CweAbstractionEnum.PILLAR:
                color = "#db0054"
                size = 30
                label_class = LabelClassEnum.BIG 
            case CweAbstractionEnum.CLASS:
                color = "#ff6200"
                size = 18
                label_class = LabelClassEnum.MEDIUM 
            case CweAbstractionEnum.BASE:
                color = "#ffbb00"
                size = 10
                label_class = LabelClassEnum.SMALL 
            case CweAbstractionEnum.VARIANT:
                color = "#e8e66b"
                size = 10
                label_class = LabelClassEnum.SMALL 
            case CweAbstractionEnum.COMPOUND:
                color = "#9ac20c"
                size = 10
                label_class = LabelClassEnum.SMALL 
            case _:
                color = "#e5f7a6"
                size = 7
                label_class = LabelClassEnum.SMALL 

        G_cwe.nodes[node]["color"] = color
        G_cwe.nodes[node]["size"] = size
        G_cwe.nodes[node]["label"] = cwe_collection.CWEs[node].Name
        G_cwe.nodes[node]["label_class"] = label_class
        G_cwe.nodes[node]["type"] = SecurityDataEnum.CWE
        G_cwe.nodes[node]["abstraction"] = cwe_collection.CWEs[node].Abstraction
        G_cwe.nodes[node]["url"] = f"https://cwe.mitre.org/data/definitions/{cwe_collection.CWEs[node].Number}.html"
    
    return G_cwe

def save_cwe_subgraphs(cwe_graph: nx.DiGraph, cwe_collection: CweCollection, output_dir: str) -> None:
    for cwe in cwe_collection.CWEs.values():
        if(cwe.Abstraction == CweAbstractionEnum.PILLAR or cwe.Abstraction == CweAbstractionEnum.CLASS):
            nodes_rbfs = reverse_bfs(cwe_graph, cwe.ID)
            cwe_subgraph = cwe_graph.subgraph(nodes_rbfs)
            save_graph_json(cwe_subgraph, os.path.join(output_dir, f"{cwe.ID}.json"))

def save_cwe_md(cwe_collection: CweCollection, md_filepath: str) -> None:
    pillar_cwe : List[Cwe] = []
    class_cwe : List[Cwe] = []

    for cwe in cwe_collection.CWEs.values():
        if cwe.Abstraction == CweAbstractionEnum.PILLAR:
            pillar_cwe.append(cwe)
        elif cwe.Abstraction == CweAbstractionEnum.CLASS:
            class_cwe.append(cwe)

    sorted_pillar_cwe = sorted(pillar_cwe, key=lambda x: x.Name)
    sorted_class_cwe = sorted(class_cwe, key=lambda x: x.Name)
    md = []

    md.append("## List of Pillar CWEs with class CWEs")
    for pil in sorted_pillar_cwe:
        md.append(f"### [{pil.ID} {pil.Name}](../visualizer.html?jsonfile={pil.ID}.json)")
        for cla in sorted_class_cwe:
            if cla.Related_CWEs:
                for rel in cla.Related_CWEs:
                    if rel.CWE_ID == pil.ID and rel.Nature == RelatedCweNatureEnum.CHILD_OF:
                        md.append(f"- [{cla.ID} {cla.Name}](../visualizer.html?jsonfile={cla.ID}.json)")
        md.append("")

    with open(md_filepath, "w") as f:
        f.write('\n'.join(md))

def reverse_bfs(graph, start):
    visited = set()
    queue = [start]
    while queue:
        node = queue.pop(0)
        if node not in visited:
            visited.add(node)
            queue.extend(set(graph.predecessors(node)) - visited)
    return visited

def main():
    parser = argparse.ArgumentParser(description="Generate graphs from CAPEC and CWE data.")
    parser.add_argument("--capec-json", required=True, help="Path to CAPEC JSON file.")
    parser.add_argument("--cwe-json", required=True, help="Path to CWE JSON file.")
    parser.add_argument("--graph-dir", required=True, help="Directory to save graph JSON files.")
    parser.add_argument("--md-dir", required=True, help="Directory to save markdown files.")
    args = parser.parse_args()

    os.makedirs(args.graph_dir, exist_ok=True)
    os.makedirs(args.md_dir, exist_ok=True)

    print("Creating Capec Graphs")
    with open(args.capec_json, "r") as f:
        capec_collection = CapecCollection.model_validate_json(f.read())
    
    G_capec = capec_graph(capec_collection)
    print("saving CAPEC full graph")
    save_graph_json(G_capec, os.path.join(args.graph_dir, "CAPEC-FULL.json"))
    
    print("Saving META CAPEC subgraphs")
    save_capec_subgraphs(G_capec, capec_collection, args.graph_dir)

    print("Saving CAPEC index markdown file")
    save_capec_md(capec_collection, os.path.join(args.md_dir, "CAPECs.md"))

    print("Creating Cwe Graphs")
    with open(args.cwe_json, "r") as f:
        cwe_collection = CweCollection.model_validate_json(f.read())
    
    G_cwe = cwe_graph(cwe_collection)
    print("Saving full CWE Graph")
    save_graph_json(G_cwe, os.path.join(args.graph_dir, "CWE-FULL.json"))

    print("Saving Pillar and Class subgraphs")
    save_cwe_subgraphs(G_cwe, cwe_collection, args.graph_dir)

    print("Saving CWE index markdown file")
    save_cwe_md(cwe_collection, os.path.join(args.md_dir, "CWEs.md"))

if __name__ == "__main__":
    main()