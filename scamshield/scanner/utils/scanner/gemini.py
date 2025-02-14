import google.generativeai as genai
import json
import os
# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# Load Gemini model
model = genai.GenerativeModel("gemini-pro")

def detect_website(content, url):
    if not content or content.startswith("Error"):
        return {"label": "unknown"}
    
    prompt = f"""
    Analyze the following webpage content and classify it as 'phishing', 'piracy', or 'legitimate'. 
    Return the result in JSON format with 'label' and 'score' fields.
    URL: {url}
    
    Content:
    {content[:1000]}
    
    Expected JSON response format:
    {{
        "label": "phishing/piracy/legitimate/unknown/hightrust",
        "explainer": "Optional explanation of the classification",
    }}
    """

    response = model.generate_content(prompt)
    
    try:
        return json.loads(response.text)  # Parse JSON from Gemini response
    except json.JSONDecodeError:
        return {"label": "unknown"}  # Handle invalid responses
