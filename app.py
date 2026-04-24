from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from scanner import run_scan
from vulscan_geo import lookup_geo, get_topology
from vulscan_risk import assess_risk
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target")
    ports = data.get("ports")
    threads = int(data.get("threads", 10))
    timeout = float(data.get("timeout", 1.0))
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Run the scan logic
    results = run_scan(target, ports, threads, timeout)
    
    if "error" in results:
        return jsonify(results), 400

    # Enrich with risk assessment
    risk_data = assess_risk(results)
    results["risk"] = risk_data
        
    return jsonify(results)

@app.route("/api/geo", methods=["POST"])
def geo():
    data = request.json
    target_ip = data.get("target_ip")
    
    if not target_ip:
        return jsonify({"error": "target_ip is required"}), 400
    
    # Get geo + topology (traceroute may take time)
    topology_data = get_topology(target_ip)
    
    return jsonify(topology_data)

if __name__ == "__main__":
    os.makedirs("static/css", exist_ok=True)
    os.makedirs("static/js", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    
    app.run(host="0.0.0.0", port=5000, debug=True)
