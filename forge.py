import json, os

def forge_payloads(file_path, output_json, category, severity):

    arsenal = []

    try:
        with open(file_path, 'r', encoding= 'utf-8') as f:
            lines = f.readlines()

    except FileNotFoundError:
        print(f"Error! couldn't find {file_path}")
        return

    for line in lines:
        payload = line.strip()

        if payload and not payload.startswith('#'):
            arsenal.append({
                "type":category,
                "payload": payload,
                "severity": severity
            })

    with open(output_json, 'w', encoding= 'utf-8') as outfile:
        json.dump(arsenal, outfile)

if __name__ == "__main__":
    forge_payloads(
        file_path='data/fuzzdb_raw_sqli.txt',
        output_json='data/fuzzdb_sqli_arsenal.json',
        category='FuzzDB Cross-Platform SQLi',
        severity='High'
    )