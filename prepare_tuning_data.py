import csv
import json
import random

def main():
    # Load the downloaded tsv file
    samples = []
    with open("sms_spam.tsv", "r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            if len(row) == 2:
                label, text = row
                samples.append((label, text))

    # Separate into ham and spam
    ham_samples = [s for s in samples if s[0] == "ham"]
    spam_samples = [s for s in samples if s[0] == "spam"]

    print(f"Loaded {len(ham_samples)} safe messages and {len(spam_samples)} spam/fraud messages.")

    # Select a balanced subset (e.g., 150 of each for a quick and cost-effective fine-tune)
    num_samples = min(150, len(ham_samples), len(spam_samples))
    selected_ham = random.sample(ham_samples, num_samples)
    selected_spam = random.sample(spam_samples, num_samples)

    all_selected = selected_ham + selected_spam
    random.shuffle(all_selected)

    tuning_data = []
    for label, text in all_selected:
        user_prompt = f"Analyze this message for fraud signals:\n\n{text}"
        
        if label == "spam":
            expected_response = {
                "risk_score": 90,
                "risk_level": "HIGH",
                "summary": "This message is a suspicious marketing or prize scam attempt.",
                "reasons": [
                    "Contains unsolicited promotional or winning claims",
                    "Requests contact or response to urgent claims",
                    "Uses typical spam/fraud language and formatting"
                ],
                "action": "BLOCK",
                "what_to_do": "Do not reply, click any links, or call the number; delete the message."
            }
        else:
            expected_response = {
                "risk_score": 0,
                "risk_level": "LOW",
                "summary": "This is a normal, safe conversational message.",
                "reasons": [
                    "Purely conversational with no suspicious intent",
                    "Contains no financial demands or credential links",
                    "No urgent threats or impersonation triggers present"
                ],
                "action": "TRUST",
                "what_to_do": "This message is safe to reply to or read."
            }
            
        tuning_data.append({
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}]
                },
                {
                    "role": "model",
                    "parts": [{"text": json.dumps(expected_response)}]
                }
            ]
        })

    # Write to jsonl
    with open("gemini_tuning_data.jsonl", "w", encoding="utf-8") as f:
        for item in tuning_data:
            f.write(json.dumps(item) + "\n")

    print(f"Successfully created gemini_tuning_data.jsonl with {len(tuning_data)} examples!")

if __name__ == "__main__":
    main()
