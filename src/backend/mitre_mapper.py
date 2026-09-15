import os
import json
from pathlib import Path

def extract_mitre_data():
    # Paths are relative to this script's location
    base_dir = Path(__file__).parent.parent
    data_dir = base_dir / "data" / "mitre-enterprise-attack-patterns"
    output_file = base_dir / "backend" / "mapped_techniques.json"
    
    if not data_dir.exists():
        print(f"Error: Directory {data_dir} does not exist.")
        return

    mapped_techniques = []
    
    # Iterate through all .json files in the directory
    for filepath in data_dir.glob("*.json"):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            for obj in data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    # Extract technique_id
                    technique_id = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            technique_id = ref.get("external_id")
                            break
                            
                    if not technique_id:
                        continue  # Skip if it doesn't have a MITRE ID
                        
                    # Extract name and description
                    name = obj.get("name", "Unknown Name")
                    description = obj.get("description", "No description available.")
                    
                    # Extract tactic
                    tactics = []
                    for kc in obj.get("kill_chain_phases", []):
                        if kc.get("kill_chain_name") == "mitre-attack":
                            phase = kc.get("phase_name")
                            if phase:
                                tactics.append(phase)
                                
                    tactic = ", ".join(tactics) if tactics else "Unknown Tactic"
                    
                    mapped_techniques.append({
                        "technique_id": technique_id,
                        "name": name,
                        "description": description,
                        "tactic": tactic
                    })
                    
        except json.JSONDecodeError:
            print(f"Warning: Failed to parse JSON in file {filepath.name}")
        except Exception as e:
            print(f"Warning: Unexpected error processing {filepath.name}: {e}")
            
    # Save the consolidated mapping to a JSON file
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(mapped_techniques, f, indent=4)
        print(f"Successfully mapped {len(mapped_techniques)} techniques and saved to {output_file.relative_to(base_dir)}")
    except Exception as e:
        print(f"Error: Failed to write to {output_file}: {e}")

if __name__ == "__main__":
    extract_mitre_data()
