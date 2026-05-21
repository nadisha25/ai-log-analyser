import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze_event_with_ai(event_row):
    event_description = f"""
    Timestamp: {event_row.get('timestamp', 'unknown')}
    IP Address: {event_row.get('ip_address', 'unknown')}
    User: {event_row.get('user', 'unknown')}
    Action: {event_row.get('action', 'unknown')}
    Status Code: {event_row.get('status_code', 'unknown')}
    Details: {event_row.get('details', 'unknown')}
    Risk Type: {event_row.get('risk_type', 'unknown')}
    """

    prompt = f"""Analyze this server log event as a cybersecurity analyst.

EVENT:
{event_description}

Reply with ONLY this JSON, no other text:
{{"risk_level": "High", "risk_score": 8, "summary": "one sentence here", "why_suspicious": "2-3 sentences here", "recommended_action": "one sentence here"}}

Rules:
- risk_level must be exactly one of: High, Medium, Low
- risk_score must be a number from 1-10
- No markdown, no backticks, just raw JSON"""

    try:
        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst. Reply only with raw JSON. No markdown. No backticks. No explanation."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=300
        )

        response_text = response.choices[0].message.content.strip()

        # Aggressively clean the response
        response_text = response_text.replace("```json", "").replace("```", "").strip()

        # Find the JSON object — look for { and }
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        if start != -1 and end != 0:
            response_text = response_text[start:end]

        result = json.loads(response_text)

        # Validate risk_level is one of the expected values
        if result.get('risk_level') not in ['High', 'Medium', 'Low']:
            result['risk_level'] = 'High'  # default to High if unclear

        return result

    except Exception as e:
        print(f"AI analysis failed: {e}")
        return {
            "risk_level": "High",
            "risk_score": 7,
            "summary": "Suspicious activity detected requiring immediate review",
            "why_suspicious": "This event matches known attack patterns and requires investigation",
            "recommended_action": "Review immediately and verify with security team"
        }


def analyze_all_suspicious_events(suspicious_df):
    print("\n=== AI RISK ANALYSIS (powered by Groq) ===")
    print(f"Sending {len(suspicious_df)} events to AI...\n")

    results = []

    for index, row in suspicious_df.iterrows():
        print(f"Analyzing event {index + 1}/{len(suspicious_df)}: "
              f"{row.get('user', '?')} - {row.get('action', '?')}")

        analysis = analyze_event_with_ai(row.to_dict())

        result = {
            "timestamp": str(row.get('timestamp', '')),
            "ip_address": row.get('ip_address', ''),
            "user": row.get('user', ''),
            "action": row.get('action', ''),
            "details": row.get('details', ''),
            "risk_type": row.get('risk_type', ''),
            "ai_risk_level": analysis.get('risk_level', 'High'),
            "ai_risk_score": analysis.get('risk_score', 7),
            "ai_summary": analysis.get('summary', ''),
            "ai_why_suspicious": analysis.get('why_suspicious', ''),
            "ai_recommended_action": analysis.get('recommended_action', '')
        }

        results.append(result)

        print(f"  -> Risk Level : {analysis.get('risk_level', '?')} "
              f"(Score: {analysis.get('risk_score', '?')}/10)")
        print(f"  -> {analysis.get('summary', '')}")
        print()

    return results