# modules/Ranking.py

import json

def rank_hypotheses_function():
    # Load hypotheses from JSON file
    with open("data/validated_hypotheses.json", "r") as f:
        hypotheses = json.load(f)

    # Define weightage for each parameter
    weights = {
        "severity": 3,
        "windows_event_id_criticality": 2,
        "event_id_count": 1,
        "number_of_unique_events": 1,
        "nature_of_evidence": 2,
    }

    # Define scoring for severity and criticality
    severity_scores = {
        "Low": 1.0,
        "Medium": 3.0,
        "High": 5.0,
    }

    windows_event_id_criticality_scores = {
        "Low": 1.0,
        "Medium": 3.0,
        "High": 5.0,
    }

    # Nature of evidence scoring
    nature_of_evidence_scores_map = {
        "hypothesis-1": 2.0,
        "hypothesis-2": 1.5,
        "hypothesis-3": 2.0,
        "hypothesis-4": 2.0,
        "hypothesis-5": 2.0,
        "hypothesis-6": 1.0,
        "hypothesis-7": 0.5,
        "hypothesis-8": 2.0,
        "hypothesis-9": 2.0,
        "hypothesis-10": 2.0,
        "hypothesis-11": 2.0,
        "hypothesis-12": 1.5,
        "hypothesis-13": 2.0,
        "hypothesis-14": 2.0,
        "hypothesis-15": 1.5,
    }

    # Scoring function for each hypothesis
    def calculate_score(hypothesis):
        severity_value = severity_scores[hypothesis["severity"]]

        first_event = next(iter(hypothesis["validation"].values()))
        criticality_value = windows_event_id_criticality_scores[first_event["criticality"]]

        event_id_count = sum(event["count"] for event in hypothesis["validation"].values())
        if event_id_count <= 10:
            event_id_count_score = 1.0
        elif event_id_count <= 100:
            event_id_count_score = 2.0
        elif event_id_count <= 500:
            event_id_count_score = 3.0
        elif event_id_count <= 1000:
            event_id_count_score = 4.0
        else:
            event_id_count_score = 5.0

        number_of_unique_events = len(hypothesis["validation"])
        if number_of_unique_events <= 2:
            number_of_unique_events_score = 1.0
        elif number_of_unique_events <= 5:
            number_of_unique_events_score = 2.0
        else:
            number_of_unique_events_score = 3.0

        nature_of_evidence_score = float(nature_of_evidence_scores_map[hypothesis["id"]])

        score = (severity_value * weights["severity"] +
                 criticality_value * weights["windows_event_id_criticality"] +
                 event_id_count_score * weights["event_id_count"] +
                 number_of_unique_events_score * weights["number_of_unique_events"] +
                 nature_of_evidence_score * weights["nature_of_evidence"])

        return float(score)

    # Calculate scores for all hypotheses
    hypotheses_with_scores = []
    for hypothesis in hypotheses:
        score = calculate_score(hypothesis)
        hypotheses_with_scores.append({
            "id": hypothesis["id"],
            "score": score,
            "severity": severity_scores[hypothesis["severity"]],
            "windows_event_id_criticality": windows_event_id_criticality_scores[next(iter(hypothesis["validation"].values()))["criticality"]]
        })

    # Sort by score, and break ties by severity first, then by criticality
    hypotheses_with_scores.sort(
        key=lambda h: (h["score"], h["severity"], h["windows_event_id_criticality"]),
        reverse=True
    )

    # Assign ranks and add them to the original hypotheses
    for rank, hypothesis in enumerate(hypotheses_with_scores, start=1):
        hypothesis_id = hypothesis['id']
        
        for h in hypotheses:
            if h['id'] == hypothesis_id:
                h['score'] = hypothesis['score']
                h['rank'] = rank

    # Save updated hypotheses with scores and ranks back to the file
    with open("data/ranked_hypotheses.json", "w") as f:
        json.dump(hypotheses, f, indent=4)

    return hypotheses  # Return the updated hypotheses with scores and ranks





