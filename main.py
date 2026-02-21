import subprocess

print("->Parsing logs")
subprocess.run(["python3", "src/parse.py"])

print("->Generating features")
subprocess.run(["python3", "src/feature.py"])

print("->Running anomaly detection")
subprocess.run(["python3", "src/model.py"])

print("->Generating threat report")
subprocess.run(["python3", "src/report.py"])

print("\nPipeline execution complete.")
