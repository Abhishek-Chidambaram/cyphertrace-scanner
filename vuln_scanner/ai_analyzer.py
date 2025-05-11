# vuln_scanner/ai_analyzer.py
import os
import json
from .models import ScanResult # Import ScanResult class from the same package
from openai import OpenAI, APIError # Import OpenAI library

# Configuration for the Groq API call
# Choose a model available on Groq's free tier, e.g., llama3-8b-8192 or mixtral-8x7b-32768
# Check Groq's documentation for currently available free models
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama3-8b-8192")
# Groq API endpoint
GROQ_API_BASE = "https://api.groq.com/openai/v1"

# Note: Temperature/Top P might be handled differently or use defaults

def get_api_key(config: dict) -> str | None:
    """
    Retrieves the Groq API key.
    Prioritizes environment variable GROQ_API_KEY, then config file.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if api_key:
        print("Info: Using Groq API key from GROQ_API_KEY environment variable.")
        return api_key

    # Fallback to config file (less secure for keys)
    if config and "api_keys" in config and "groq" in config["api_keys"]:
        api_key = config["api_keys"]["groq"]
        if api_key and api_key != "YOUR_GROQ_API_KEY_HERE": # Check for placeholder
            print("Info: Using Groq API key from config.yaml.")
            return api_key
        elif api_key == "YOUR_GROQ_API_KEY_HERE":
            print("Warning: Found placeholder Groq API key in config.yaml.")

    print("Warning: Groq API key not found in environment variables or config.yaml. AI summary will be skipped.")
    return None

def generate_vulnerability_summary(results: list[ScanResult], api_key: str) -> str | None:
    """
    Generates a summary of vulnerabilities using the Groq API (OpenAI compatible).
    'results' is a list of ScanResult objects.
    """
    if not results:
        return "Scan completed with no vulnerabilities found."
    if not api_key:
        return "AI Summary skipped: Groq API key not available."

    # Prepare a concise representation of results for the prompt
    vulnerabilities_for_prompt = []
    for result in results[:20]: # Limit prompt size
        vuln = result.vulnerability
        pkg = result.package
        vulnerabilities_for_prompt.append({
            "package": f"{pkg.name}@{pkg.version}",
            "id": vuln.cve_id,
            "severity": vuln.severity,
            "score": float(vuln.cvss_v3_score) if vuln.cvss_v3_score is not None else None, # Ensure float
            "description_snippet": vuln.description[:150] + "..." if vuln.description and len(vuln.description) > 150 else vuln.description
        })

    results_json_str = json.dumps(vulnerabilities_for_prompt, indent=2)

    # --- Craft the Prompt ---
    prompt = f"""You are a cybersecurity analyst assistant explaining vulnerability scan results.
    Here are the top vulnerabilities detected (in JSON format):

    {results_json_str}

    Please provide a concise, non-repetitive summary of the most critical vulnerabilities, their potential impact, and general remediation advice. Avoid repeating package names. Limit your response to 5-7 sentences for a technical audience.
    """

    print(f"Info: Sending request to Groq API ({GROQ_MODEL}) for summary...")
    try:
        client = OpenAI(
            api_key=api_key,
            base_url=GROQ_API_BASE
        )
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a helpful cybersecurity assistant."},
                {"role": "user", "content": prompt,}
            ],
            model=GROQ_MODEL,
            temperature=0.2,
            # max_tokens=1024, # Optional
        )
        # Check for content in the response choice
        if chat_completion.choices and chat_completion.choices[0].message:
             summary = chat_completion.choices[0].message.content
             print("Info: Received summary from Groq.")
             return summary
        else:
             # Handle cases where response structure might be unexpected or empty
             print(f"Warning: Groq response structure unexpected or empty choice. Full response: {chat_completion}")
             return "AI Summary generation failed: Unexpected response structure from API."

    # --- MORE SPECIFIC ERROR HANDLING ---
    except APIError as e:
        # Handle API error here, e.g. retry or log
        print(f"Groq API returned an API Error: {e.status_code}")
        print(f"Response: {e.response}")
        print(f"Body: {e.body}")
        return f"AI Summary failed: API Error ({e.status_code} - Check Groq status or API key)."
    except Exception as e:
        # Catch other potential errors like network issues, unexpected exceptions
        import traceback
        print(f"An unexpected error occurred calling Groq API: {e}")
        print(traceback.format_exc()) # Print full traceback for debugging
        return f"AI Summary generation failed due to an unexpected error: {type(e).__name__}"
    # --- END ERROR HANDLING ---