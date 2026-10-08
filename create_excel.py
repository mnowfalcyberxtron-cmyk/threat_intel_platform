import csv

with open("cve_scores_feedly.md", "r") as f:
    lines = f.readlines()

csv_file = "cve_scores.csv"

with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["CVE ID", "Score"])
    
    for line in lines[2:]:
        parts = line.strip().split("|")
        if len(parts) >= 3:
            cve = parts[1].strip()
            score = parts[2].strip()
            writer.writerow([cve, score])

print(f"Created {csv_file}")
