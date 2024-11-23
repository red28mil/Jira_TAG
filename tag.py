import requests
from requests.auth import HTTPBasicAuth
import json

# Jira credentials
JIRA_URL = "https://<>.atlassian.net/rest/api/3/issue"
JIRA_EMAIL = ""
JIRA_API_TOKEN = "4"
JIRA_PROJECT_KEY = "S"  # Replace with your project key

# MITRE CVE API base URL
MITRE_API_URL = "https://cveawg.mitre.org/api/cve/"

# Hypothetical CISA KEV API URL (replace with the actual URL if available)
CISA_KEV_API_URL = "https://cisa.gov/api/kev/"


def fetch_cve_details(cve_id):
    """Fetch CVE details from MITRE's CVE.org API and check CISA KEV."""
    try:
        response = requests.get(MITRE_API_URL + cve_id)
        response.raise_for_status()
        cve_data = response.json()

        # Extract relevant details
        description = cve_data.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "N/A")
        title = cve_data.get("cve", {}).get("id", "N/A")
        cvss_score = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", "N/A")
        severity = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("overallSeverity", "N/A")
        cvss_vector_string = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("vectorString", "N/A")

        # Check CISA KEV (replace with actual implementation)
        cisa_kev_result = check_cisa_kev(cve_id)

        return {
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "cvss_vector_string": cvss_vector_string,
            "in_cisa_kev": cisa_kev_result,
        }
    except Exception as e:
        print(f"Error fetching CVE details: {e}")
        return None


def check_cisa_kev(cve_id):
    """Hypothetical function to check CISA KEV (replace with actual implementation)."""
    cisa_api_url = CISA_KEV_API_URL + cve_id
    try:
        response = requests.get(cisa_api_url)
        response.raise_for_status()
        return True  # CVE found in CISA KEV
    except requests.exceptions.RequestException:
        return False  # CVE not found in CISA KEV (or handle other errors)


def create_jira_issue(cve_details_list):
    """Create a Jira issue using the Jira REST API for a list of CVE details."""
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    # Build formatted description with multiple CVEs
    description_content = []
    for cve_data in cve_details_list:
        cisa_kev_text = "**In CISA KEV:** Yes" if cve_data["in_cisa_kev"] else "**In CISA KEV:** No"
        description_content.append(
            {
                "type": "paragraph",
                "content": [
                    {"text": "CVE ID:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": f" {cve_data['cve_id']}", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "CVSS Base Score:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": f" {cve_data['cvss_score']}", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "Severity:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": f" {cve_data['severity']}", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "CVSS Vector String:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": f" {cve_data['cvss_vector_string']}", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "In CISA KEV:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": f" {cisa_kev_text}", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "Description:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": f" {cve_data['description']}", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "Location:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": " [Location of the vulnerability]", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "Affected Software:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": " [Affected software versions]", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "Detection Tool:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": " [Detection tool or method]", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "Recommended Treatment:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": " [Recommended actions to mitigate the vulnerability]", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line

                    {"text": "Output Assessment:", "type": "text", "marks": [{"type": "strong"}]},
                    {"text": " [Assessment of the vulnerability's impact and potential consequences]", "type": "text"},
                    {"text": "\n", "type": "text"},  # New line
                ],
            }
        )

    adf_description = {
        "type": "doc",
        "version": 1,
        "content": description_content,
    }

    issue_payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": "Multiple CVEs Found",  # Adjust summary as needed
            "description": adf_description,
            "issuetype": {"name": "Task"},  # Change issue type as needed
            "labels": ["SPASER", "CVE_Vulnerability", "Triage"]  # Add more labels as needed
        }
    }

    try:
        response = requests.post(
            JIRA_URL,
            headers=headers,
            data=json.dumps(issue_payload),
            auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN),
        )
        if response.status_code == 201:
            print(f"Issue created successfully: {response.json()['key']}")
        else:
            print(f"Failed to create issue: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error creating Jira issue: {e}")


def main():
    """Main script to fetch multiple CVE details and create a Jira issue."""
    cve_details_list = []

    while True:
        cve_id = input("Enter a CVE ID (e.g., CVE-2023-1234) or 'q' to quit: ").strip()
        if cve_id.lower() == "q":
            break

        cve_details = fetch_cve_details(cve_id)
        if cve_details:
            cve_details_list.append(cve_details)
        else:
            print("Failed to fetch CVE details. Please try again.")

    if cve_details_list:
        create_jira_issue(cve_details_list)
    else:
        print("No CVEs provided. Exiting.")


if __name__ == "__main__":
    main()
