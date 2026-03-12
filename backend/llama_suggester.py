import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def get_taint_fix_suggestions(code):
    try:
        numbered_code = "\n".join(
            f"{i+1}: {line}" for i, line in enumerate(code.split("\n"))
        )

        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": """
You are a strict taint analysis engine.

OUTPUT RULES:
- Return clean HTML only.
- Use headings (<h3>) for each vulnerability.
- Say exactly: "Vulnerability occurred at line X"
- Do NOT highlight the line number.
- On the next line, show ONLY the vulnerable code line.
- Highlight ONLY the code line using:
  <span style="color:red; font-weight:bold;">
- Keep spacing compact (no large gaps).
- Provide a secure fix with heading <h4>Secure Fix</h4>
- Always generate complete fixes.
"""
                },
                {
                    "role": "user",
                    "content": f"""
Analyze this numbered code and detect all taint vulnerabilities.

For each vulnerability:
1. Add a heading with vulnerability name.
2. Write: Vulnerability occurred at line X
3. Next line: show ONLY the exact vulnerable code line highlighted in red.
4. Explain briefly why it is dangerous.
5. Provide full secure fix.

Code:
{numbered_code}
"""
                }
            ],
            temperature=0.1,
            max_tokens=1600
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        print("LLaMA Error:", str(e))
        return "<h3>Error</h3><p>AI suggestion generation failed.</p>"
