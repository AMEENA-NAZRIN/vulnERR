import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_PATH = "../best_codebert_vuldet"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, use_fast=False)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.eval()

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

def analyze_code(code, threshold=0.20, max_length=510, stride=256):
    
    # ── Guard: empty code ────────────────────────────────
    if not code or not code.strip():
        return {
            "status":       "safe",
            "severity":     "None",
            "message":      "Empty file — nothing to analyze",
            "confidence":   0.0,
            "risky_chunks": [],
            "chunk_probs":  [],
            "max_prob":     0.0,
            "threshold":    threshold
        }

    tokens = tokenizer(code, add_special_tokens=False, truncation=True)["input_ids"]

    # ── Guard: tokenization returned nothing ─────────────
    if not tokens:
        return {
            "status":       "safe",
            "severity":     "None", 
            "message":      "Could not tokenize file",
            "confidence":   0.0,
            "risky_chunks": [],
            "chunk_probs":  [],
            "max_prob":     0.0,
            "threshold":    threshold
        }

    chunk_probs = []
    start = 0
    while start < len(tokens):
        end          = min(start + max_length, len(tokens))
        chunk_tokens = tokens[start:end]

        input_ids = [tokenizer.cls_token_id] + chunk_tokens[:508] + [tokenizer.sep_token_id]
        attn_mask = [1] * len(input_ids)
        padding   = max_length + 2 - len(input_ids)
        input_ids += [tokenizer.pad_token_id] * padding
        attn_mask += [0] * padding

        inputs = {
            "input_ids":      torch.tensor([input_ids]).to(device),
            "attention_mask": torch.tensor([attn_mask]).to(device)
        }

        with torch.no_grad():
            outputs    = model(**inputs)
            probs      = torch.softmax(outputs.logits, dim=-1)
            vuln_prob  = probs[0][1].item()
            chunk_probs.append(vuln_prob)

        if end == len(tokens): break
        start += stride

    # ── Aggregate ─────────────────────────────────────────
    final_prob   = max(chunk_probs)
    pred         = 1 if final_prob > threshold else 0
    confidence   = final_prob if pred == 1 else 1 - final_prob
    risky_chunks = [i + 1 for i, p in enumerate(chunk_probs) if p > threshold]

    if pred == 1:
        return {
            "status":       "vulnerable",
            "severity":     "High",
            "message":      "Potential taint vulnerability detected",
            "confidence":   round(confidence * 100, 2),
            "risky_chunks": risky_chunks,
            "chunk_probs":  [round(p, 3) for p in chunk_probs],
            "max_prob":     round(final_prob, 3),
            "threshold":    threshold
        }
    else:
        return {
            "status":       "safe",
            "severity":     "None",
            "message":      "No taint vulnerability detected",
            "confidence":   round(confidence * 100, 2),
            "risky_chunks": [],
            "chunk_probs":  [round(p, 3) for p in chunk_probs],
            "max_prob":     round(final_prob, 3),
            "threshold":    threshold
        }