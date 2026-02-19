import subprocess

print("Step 1: Parsing logs...")
subprocess.run(["python3", "src/parse.py"])

print("Step 2: Generating features...")
subprocess.run(["python3", "src/feature.py"])

print("Step 3: Running anomaly detection...")
subprocess.run(["python3", "src/model.py"])

print("Step 4: Generating threat report...")
subprocess.run(["python3", "src/report.py"])

print("\nPipeline execution complete.")
