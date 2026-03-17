import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_PATH = "../trained_model"

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_PATH,
    use_fast=False
)

model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.eval()

def analyze_code(code):
    inputs = tokenizer(
        code,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=256
    )

    with torch.no_grad():
        outputs = model(**inputs)
        prediction = torch.argmax(outputs.logits, dim=1).item()

    if prediction == 1:
        return {
            "status": "vulnerable",
            "severity": "High",
            "message": "Potential taint vulnerability detected"
        }
    else:
        return {
            "status": "safe",
            "severity": "None",
            "message": "No taint vulnerability detected"
        }
