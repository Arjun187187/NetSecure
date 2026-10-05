from flask import Flask, render_template, request, jsonify, send_from_directory
from scanner import scan_target
from pathlib import Path
import json
from datetime import datetime

app = Flask(__name__)
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    try:
        result = scan_target(target)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = REPORT_DIR / f"scan_{stamp}.json"
        json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["report_file"] = json_path.name
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

@app.get("/reports/<path:filename>")
def reports(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
