import re
import json
import os

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def find_keys_in_code(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Regex patterns
    # tr("key"), tr('key') - with boundary check and whitespace support
    tr_pattern = re.compile(r'\btr\(\s*[\'"]([^\'"]+)[\'"]')
    # t("key"), t('key') - with boundary check
    t_pattern = re.compile(r'\bt\(\s*[\'"]([^\'"]+)[\'"]')
    # data-i18n="key", data-i18n='key'
    data_pattern = re.compile(r'data-i18n=[\'"]([^\'"]+)[\'"]')
    
    keys = set()
    keys.update(tr_pattern.findall(content))
    keys.update(t_pattern.findall(content))
    keys.update(data_pattern.findall(content))
    
    return keys

def check_duplicates(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Simple regex to find keys
    key_pattern = re.compile(r'"([^"]+)":')
    keys = key_pattern.findall(content)
    
    seen = set()
    duplicates = set()
    for k in keys:
        if k in seen:
            duplicates.add(k)
        seen.add(k)
    return duplicates

def main():
    base_dir = r"c:\Users\svenh\Downloads\install_backup_pro\installer_bundle"
    code_path = os.path.join(base_dir, "backup_app_v7_4.py")
    de_path = os.path.join(base_dir, "i18n", "lang_de.json")
    en_path = os.path.join(base_dir, "i18n", "lang_en.json")
    
    print(f"Scanning {code_path}...")
    code_keys = find_keys_in_code(code_path)
    print(f"Found {len(code_keys)} unique keys in code.")
    
    print(f"Loading {de_path}...")
    de_json = load_json(de_path)
    de_keys = set(de_json.keys())
    
    print(f"Loading {en_path}...")
    en_json = load_json(en_path)
    en_keys = set(en_json.keys())
    
    # Check for duplicates in JSON files (raw text check)
    de_dupes = check_duplicates(de_path)
    if de_dupes:
        print(f"WARNING: Duplicate keys in lang_de.json: {de_dupes}")
        
    en_dupes = check_duplicates(en_path)
    if en_dupes:
        print(f"WARNING: Duplicate keys in lang_en.json: {en_dupes}")

    # Missing in DE
    missing_de = code_keys - de_keys
    if missing_de:
        print("\nMISSING IN DE (Used in code but not in lang_de.json):")
        for k in sorted(missing_de):
            print(f"  - {k}")
    else:
        print("\nAll code keys present in DE.")

    # Missing in EN
    missing_en = code_keys - en_keys
    if missing_en:
        print("\nMISSING IN EN (Used in code but not in lang_en.json):")
        for k in sorted(missing_en):
            print(f"  - {k}")
    else:
        print("\nAll code keys present in EN.")
        
    # Obsolete (In JSON but not in code)
    # Note: Some keys might be constructed dynamically, so this is just a hint.
    obsolete_de = de_keys - code_keys
    if obsolete_de:
        print(f"\nPOTENTIALLY OBSOLETE IN DE ({len(obsolete_de)} keys):")
        # print first 10
        for k in sorted(list(obsolete_de))[:10]:
            print(f"  - {k}")
        if len(obsolete_de) > 10:
            print("  ... and more")

    obsolete_en = en_keys - code_keys
    if obsolete_en:
        print(f"\nPOTENTIALLY OBSOLETE IN EN ({len(obsolete_en)} keys):")
        for k in sorted(list(obsolete_en))[:10]:
            print(f"  - {k}")
            
    # Consistency check between DE and EN
    de_not_en = de_keys - en_keys
    en_not_de = en_keys - de_keys
    
    if de_not_en:
        print(f"\nIn DE but missing in EN ({len(de_not_en)} keys):")
        for k in sorted(de_not_en):
            print(f"  - {k}")
            
    if en_not_de:
        print(f"\nIn EN but missing in DE ({len(en_not_de)} keys):")
        for k in sorted(en_not_de):
            print(f"  - {k}")

if __name__ == "__main__":
    main()
