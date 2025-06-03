#!/usr/bin/env python3
from __future__ import annotations

import io
import os
import sys
import tarfile
import copy
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Tuple, Set, Dict
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

TAG_SETS: Dict[str, Dict[str, str]] = {
    "ip": {
        "group": "IPHostGroup",
        "list": "IPHostList",
        "ref": "IPHost",
        "host": "IPHost",
    },
    "fqdn": {
        "group": "FQDNHostGroup",
        "list": "FQDNHostList",
        "ref": "FQDNHost",
        "host": "FQDNHost",
    },
}


def detect_object_type(tree: ET.ElementTree) -> str:
    root = tree.getroot()
    for obj_type, tags in TAG_SETS.items():
        if root.find(f".//{tags['group']}") is not None:
            return obj_type
    sys.exit("\nUnbekanntes Host‑Schema: weder IP‑ noch FQDN‑Objekte gefunden!\n")


def find_source_tar(search_dir: str | None = None) -> str:
    if search_dir is None:
        search_dir = os.getcwd()

    candidates = [
        f for f in os.listdir(search_dir)
        if f.lower().endswith('.tar') and 'api-' in f.lower()
    ]

    if not candidates:
        sys.exit("\nKein passendes .tar-Archiv gefunden!\n")

    candidates.sort(
        key=lambda f: os.path.getmtime(os.path.join(search_dir, f)),
        reverse=True,
    )
    return os.path.join(search_dir, candidates[0])


def load_xml_from_tar(tar_path: str) -> Tuple[ET.ElementTree, str]:
    try:
        with tarfile.open(tar_path) as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.lower().endswith('.xml'):
                    extracted = tar.extractfile(member)
                    if extracted:
                        tree = ET.parse(extracted)
                        return tree, member.name
        sys.exit("\nKeine XML-Datei im Archiv!\n")
    except (tarfile.TarError, FileNotFoundError) as err:
        sys.exit(f"Archivfehler: {err}\n")


def list_groups(tree: ET.ElementTree, tags: Dict[str, str]) -> List[str]:
    names = []
    for grp in tree.getroot().findall(f".//{tags['group']}"):
        name = grp.findtext('Name', '').strip()
        if name:
            names.append(name)
    
    names = sorted(set(names))
    
    if not names:
        logger.warning("\nKeine Gruppen gefunden!\n")
        return []
    
    print(f"\nVerfügbare Gruppen ({len(names)}):")
    for idx, name in enumerate(names, 1):
        print(f"{idx:3d}: {name}")
    print()
    return names


def parse_group_selection(
    selection: str,
    all_groups: List[str],
) -> Tuple[List[str], List[str]]:
    if not selection.strip():
        return [], []
    requested: Set[str] = set()
    invalid: List[str] = []
    parts = [p.strip() for p in selection.split(',') if p.strip()]
    for part in parts:
        if '-' in part and not part.startswith('-'):
            try:
                start, end = part.split('-', 1)
                start_idx = int(start) - 1
                end_idx = int(end) - 1
                if 0 <= start_idx <= end_idx < len(all_groups):
                    for i in range(start_idx, end_idx + 1):
                        requested.add(all_groups[i])
                else:
                    invalid.append(part)
            except ValueError:
                invalid.append(part)
        elif part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(all_groups):
                requested.add(all_groups[idx])
            else:
                invalid.append(part)
        else:
            matches = [g for g in all_groups if part.lower() in g.lower()]
            if len(matches) == 1:
                requested.add(matches[0])
            elif part in all_groups:
                requested.add(part)
            else:
                invalid.append(part)
    return list(requested), invalid


def process_tree(tree: ET.ElementTree, group_names: List[str], tags: Dict[str, str]) -> ET.ElementTree:
    root = tree.getroot()
    new_root = ET.Element(root.tag, root.attrib)

    host_refs: Set[str] = set()
    groups_to_export: List[ET.Element] = []

    for grp in root.findall(f".//{tags['group']}"):
        name = grp.findtext('Name', '').strip()
        if name in group_names:
            groups_to_export.append(grp)

            for list_tag in [tags['list'], 'HostList', 'IPHostList', 'FQDNHostList']:
                lst = grp.find(list_tag)
                if lst is not None:
                    for ref in lst:
                        if ref.text and ref.text.strip():
                            host_refs.add(ref.text.strip())
                    break

    seen_hosts: Set[str] = set()
    for host in root.iter(tags['host']):
        if host.find('Name') is None:
            continue
        name = host.findtext('Name', '').strip()
        if name in host_refs and name not in seen_hosts:
            new_root.append(copy.deepcopy(host))
            seen_hosts.add(name)

    for grp in groups_to_export:
        new_root.append(copy.deepcopy(grp))

    try:
        ET.indent(new_root, space="  ")
    except AttributeError:
        pass

    return ET.ElementTree(new_root)


def export_tree_to_tar(tree: ET.ElementTree, xml_name: str, output_tar: str) -> None:
    xml_bytes = ET.tostring(tree.getroot(), encoding='utf-8', xml_declaration=True)
    try:
        with tarfile.open(output_tar, 'w') as tar:
            info = tarfile.TarInfo(name=xml_name)
            info.size = len(xml_bytes)
            info.mtime = int(datetime.now().timestamp())
            tar.addfile(info, io.BytesIO(xml_bytes))
        print(f"Export erfolgreich: {output_tar}\n")
    except tarfile.TarError as err:
        sys.exit(f"Ausgabefehler: {err}\n")


if __name__ == "__main__":
    try:
        tar_path = find_source_tar()
        print(f"\nQuell-Datei: {os.path.basename(tar_path)}")
        tree, xml_member_name = load_xml_from_tar(tar_path)
        obj_type = detect_object_type(tree)
        tags = TAG_SETS[obj_type]
        print(f"\nErkanntes Schema: {obj_type.upper()}-Hosts")
        
        all_groups = list_groups(tree, tags)
        if not all_groups:
            sys.exit("\nKeine Gruppen im XML.\n")
        
        sel = input("Gruppen wählen (z.B. 1,3,5 / 1-5 / Name): ")
        group_names, invalid = parse_group_selection(sel, all_groups)
        
        if invalid:
            print(f"\nUngültige Eingaben: " + ", ".join(invalid))
            sys.exit("\nAbbruch wegen ungültiger Eingabe!\n")
        
        if not group_names:
            sys.exit("\nKeine gültigen Gruppen ausgewählt!\n")
        
        print(f"\nAusgewählte Gruppen ({len(group_names)}):")
        for name in sorted(group_names):
            print(f"  - {name}")
        
        export_name = input("\nExportname: ").strip().replace(" ", "_")
        print()
        if not export_name:
            sys.exit("\nKein Exportname!\n")
            
        output_path = Path(f"{export_name}.tar")
        if output_path.exists():
            overwrite = input(f"\nDatei {output_path} existiert bereits. Überschreiben? (y/n): ")
            if overwrite.lower() not in ('j', 'ja', 'y', 'yes'):
                print(f"\nExport abgebrochen – Datei existiert!\n")
                sys.exit(0)
        
        new_tree = process_tree(tree, group_names, tags)
        export_tree_to_tar(new_tree, xml_member_name, str(output_path))
        
    except KeyboardInterrupt:
        print(f"\n\nExport durch Benutzer abgebrochen!\n")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\nUnerwarteter Fehler: {e}")