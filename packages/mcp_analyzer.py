from fastmcp import FastMCP
import os, json

mcp = FastMCP("Crucible Analyst")
reportsPath = '/reports/'

@mcp.tool()
def get_latest_scan_results()->str:

    if not os.path.isdir(reportsPath):
        return 'No reports folder found. Please run a scan first'

    files = sorted([f for f in os.listdir(reportsPath) if f.endswith('.json')])
    if not files:
        return 'No JSON reports found.'

    with open(os.path.join(reportsPath, files[0]), 'r') as f:
        data = json.load(f)

    return f"Latest Report ({files[0]}): Found {len(data)} potential vulnerabilities."

@mcp.tool()
def explain_vulnerability(index: int) -> str:
    files = sorted([f for f in os.listdir(reportsPath) if f.endswith('.json')], reverse=True)
    with open(os.path.join(reportsPath, files[0]), 'r') as f:
        data = json.load(f)

    if index < len(data):
        vuln = data[index]
        return json.dumps(vuln, indent=2)
    return "Invalid index."


if __name__ == "__main__":
    mcp.run()