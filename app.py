from flask import Flask, render_template, request, jsonify, send_from_directory
from scanner import scan_target, resolve_and_classify_target, discover_network
from reporting import generate_json_report, generate_pdf_report
from pathlib import Path
from datetime import datetime
import json
import re

app = Flask(__name__)

REPORT_DIR = Path("reports")
REPORT_JSON_DIR = REPORT_DIR / "json"
REPORT_PDF_DIR = REPORT_DIR / "pdf"

REPORT_DIR.mkdir(exist_ok=True)
REPORT_JSON_DIR.mkdir(parents=True, exist_ok=True)
REPORT_PDF_DIR.mkdir(parents=True, exist_ok=True)


def load_scan_reports():
    scans = []
    if not REPORT_DIR.exists():
        return scans

    # Search in reports/ and reports/json/
    json_files = list(REPORT_DIR.glob("scan_*.json")) + list(REPORT_DIR.glob("NetSecure_NS-*.json")) + list(REPORT_JSON_DIR.glob("*.json"))
    seen_ids = set()

    for filepath in json_files:
        try:
            data = json.loads(filepath.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue

            # Handle both raw scanner output and structured report payload
            if "report_metadata" in data and "assessment" in data:
                assessment_id = data["report_metadata"].get("assessment_id") or filepath.stem
                if assessment_id in seen_ids:
                    continue
                seen_ids.add(assessment_id)

                assessment = data.get("assessment", {})
                summary = data.get("summary", {})

                scans.append({
                    "assessment_id": assessment_id,
                    "asset_id": assessment.get("asset_id", "ASSET-001"),
                    "target": assessment.get("target", "Unknown"),
                    "resolved_ip": assessment.get("resolved_ip", "Unknown"),
                    "target_type": assessment.get("target_type", "UNKNOWN"),
                    "is_public": assessment.get("is_public", False),
                    "started_at": assessment.get("started_at", ""),
                    "completed_at": assessment.get("completed_at", ""),
                    "duration_seconds": assessment.get("duration_seconds", 0.0),
                    "ports_scanned": data.get("scope", {}).get("ports_scanned", 16),
                    "open_ports": len(data.get("open_ports", [])),
                    "nmap_available": data.get("scanner", {}).get("nmap_available", False),
                    "nmap_version": data.get("scanner", {}).get("nmap_version", ""),
                    "risk_summary": summary,
                    "executive_summary_data": data.get("executive_summary_data"),
                    "findings": data.get("findings", []),
                    "counts": summary.get("counts", {}),
                    "status": "COMPLETED",
                    "report_file": filepath.name
                })
            else:
                assessment_id = data.get("assessment_id") or filepath.stem.replace("scan_", "NS-")
                if assessment_id in seen_ids:
                    continue
                seen_ids.add(assessment_id)

                target = data.get("target") or data.get("ip") or "Unknown"
                resolved_ip = data.get("resolved_ip") or target
                started_at = data.get("started_at") or datetime.fromtimestamp(filepath.stat().st_mtime).isoformat(timespec="seconds")

                risk_summary = data.get("risk_summary") or {}
                counts = risk_summary.get("counts") or data.get("counts") or {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                findings = data.get("findings") or []

                scans.append({
                    "assessment_id": assessment_id,
                    "asset_id": data.get("asset_id", "ASSET-001"),
                    "target": target,
                    "resolved_ip": resolved_ip,
                    "target_type": data.get("target_type", "UNKNOWN"),
                    "is_public": data.get("is_public", False),
                    "started_at": started_at,
                    "completed_at": data.get("completed_at", started_at),
                    "duration_seconds": data.get("duration_seconds", 0.0),
                    "ports_scanned": data.get("ports_scanned", 16),
                    "open_ports": data.get("open_ports", len([f for f in findings if f.get("port", 0) > 0])),
                    "nmap_available": data.get("nmap_available", False),
                    "nmap_version": data.get("nmap_version", ""),
                    "risk_summary": {
                        "risk_score": risk_summary.get("risk_score", 100),
                        "risk_rating": risk_summary.get("risk_rating", "STRONG"),
                        "counts": counts,
                        "finding_count": len(findings),
                        "high_priority_count": counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
                    },
                    "executive_summary_data": data.get("executive_summary_data"),
                    "findings": findings,
                    "counts": counts,
                    "status": "COMPLETED",
                    "report_file": filepath.name
                })
        except Exception:
            continue

    scans.sort(key=lambda s: s.get("started_at", ""), reverse=True)
    return scans


def load_discovery_reports():
    discoveries = []
    if not REPORT_DIR.exists():
        return discoveries

    json_files = list(REPORT_DIR.glob("discovery_*.json")) + list(REPORT_DIR.glob("NetSecure_ND-*.json")) + list(REPORT_JSON_DIR.glob("*ND-*.json"))
    seen_ids = set()

    for filepath in json_files:
        try:
            data = json.loads(filepath.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue

            disc_id = data.get("discovery_id") or data.get("report_metadata", {}).get("assessment_id") or filepath.stem
            if disc_id in seen_ids:
                continue
            seen_ids.add(disc_id)

            data["report_file"] = filepath.name
            discoveries.append(data)
        except Exception:
            continue

    discoveries.sort(key=lambda d: d.get("started_at", ""), reverse=True)
    return discoveries


def get_all_assets_data():
    scans = load_scan_reports()
    discoveries = load_discovery_reports()

    assets_map = {}
    asset_seq = 1

    for disc in discoveries:
        disc_assets = disc.get("assets") or []
        for ast in disc_assets:
            ip = ast.get("ip")
            if not ip:
                continue
            if ip not in assets_map:
                assets_map[ip] = {
                    "asset_id": ast.get("asset_id") or f"ASSET-{asset_seq:03d}",
                    "ip": ip,
                    "hostname": ast.get("hostname", ""),
                    "status": ast.get("status", "UP"),
                    "target_type": ast.get("target_type", "PRIVATE"),
                    "first_discovered": ast.get("discovered_at", disc.get("started_at", "")),
                    "last_seen": ast.get("last_seen", disc.get("started_at", "")),
                    "last_assessed": None,
                    "open_ports": None,
                    "finding_count": 0,
                    "risk_score": None,
                    "risk_rating": "UNASSESSED",
                    "risk_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                    "assessment_id": None,
                    "assessment_history": []
                }
                asset_seq += 1

    for sc in scans:
        ip = sc.get("resolved_ip") or sc.get("target")
        if not ip:
            continue

        if ip not in assets_map:
            assets_map[ip] = {
                "asset_id": sc.get("asset_id") or f"ASSET-{asset_seq:03d}",
                "ip": ip,
                "hostname": "",
                "status": "UP",
                "target_type": sc.get("target_type", "UNKNOWN"),
                "first_discovered": sc.get("started_at", ""),
                "last_seen": sc.get("completed_at", sc.get("started_at", "")),
                "last_assessed": sc.get("completed_at", sc.get("started_at", "")),
                "open_ports": sc.get("open_ports", 0),
                "finding_count": len(sc.get("findings", [])),
                "risk_score": sc.get("risk_summary", {}).get("risk_score", 100),
                "risk_rating": sc.get("risk_summary", {}).get("risk_rating", "STRONG"),
                "risk_counts": sc.get("counts", {}),
                "assessment_id": sc.get("assessment_id"),
                "assessment_history": []
            }
            asset_seq += 1

        ast_entry = assets_map[ip]
        if not any(h["assessment_id"] == sc["assessment_id"] for h in ast_entry["assessment_history"]):
            ast_entry["assessment_history"].append({
                "assessment_id": sc["assessment_id"],
                "started_at": sc["started_at"],
                "completed_at": sc["completed_at"],
                "risk_score": sc.get("risk_summary", {}).get("risk_score", 100),
                "risk_rating": sc.get("risk_summary", {}).get("risk_rating", "STRONG"),
                "open_ports": sc["open_ports"],
                "finding_count": len(sc.get("findings", []))
            })

        if not ast_entry["last_assessed"] or sc["started_at"] >= ast_entry["last_assessed"]:
            ast_entry["last_assessed"] = sc["completed_at"] or sc["started_at"]
            ast_entry["open_ports"] = sc["open_ports"]
            ast_entry["finding_count"] = len(sc.get("findings", []))
            ast_entry["risk_score"] = sc.get("risk_summary", {}).get("risk_score", 100)
            ast_entry["risk_rating"] = sc.get("risk_summary", {}).get("risk_rating", "STRONG")
            ast_entry["risk_counts"] = sc.get("counts", {})
            ast_entry["assessment_id"] = sc["assessment_id"]

    return list(assets_map.values())


@app.route("/")
def index():
    return render_template("index.html")

@app.post("/api/validate-target")
def api_validate_target():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target input is required."}), 400

    try:
        info = resolve_and_classify_target(target)
        return jsonify(info)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Resolution failed: {str(exc)}"}), 500

@app.post("/api/discover")
def api_discover():
    data = request.get_json(silent=True) or {}
    network = (data.get("network") or "").strip()

    if not network:
        return jsonify({"error": "Network CIDR notation is required (e.g. 192.168.1.0/24)."}), 400

    try:
        result = discover_network(network)
        
        # Generate JSON and PDF report files
        json_path, json_file, json_payload = generate_json_report(result)
        pdf_path, pdf_file = generate_pdf_report(result)

        # Backward compatibility fallback write to reports/ root
        legacy_filename = f"discovery_{result['discovery_id']}.json"
        (REPORT_DIR / legacy_filename).write_text(json.dumps(result, indent=2), encoding="utf-8")

        result["report_file"] = json_file
        result["pdf_report_file"] = pdf_file

        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Network discovery failed: {str(exc)}"}), 500

@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    confirmed_authorized = bool(data.get("confirmed_authorized", False))

    if not target:
        return jsonify({"error": "Target input is required."}), 400

    try:
        target_info = resolve_and_classify_target(target)
        if target_info["is_public"] and not confirmed_authorized:
            return jsonify({
                "error": "Explicit authorization confirmation is required for public targets.",
                "target_type": target_info["target_type"],
                "is_public": True,
                "authorization_required": True
            }), 403

        result = scan_target(target)

        # Generate JSON and PDF security reports via reporting layer
        json_path, json_file, json_payload = generate_json_report(result)
        pdf_path, pdf_file = generate_pdf_report(result)

        # Backward compatibility fallback write
        legacy_filename = f"scan_{result['assessment_id']}.json"
        (REPORT_DIR / legacy_filename).write_text(json.dumps(result, indent=2), encoding="utf-8")

        result["report_file"] = json_file
        result["pdf_report_file"] = pdf_file

        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan execution failed: {str(exc)}"}), 500

@app.get("/api/dashboard")
def api_dashboard():
    try:
        scans = load_scan_reports()
        assets = get_all_assets_data()

        total_assets = len(assets)
        active_assets = sum(1 for a in assets if a.get("status") == "UP")
        total_assessments = len(scans)

        all_findings = []
        for sc in scans:
            all_findings.extend(sc.get("findings", []))

        total_findings_count = len(all_findings)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            r = f.get("risk", "INFO")
            if r in counts:
                counts[r] += 1

        if scans:
            overall_score = round(sum(sc.get("risk_summary", {}).get("risk_score", 100) for sc in scans) / len(scans))
        else:
            overall_score = 100

        if overall_score >= 81:
            overall_rating = "STRONG"
        elif overall_score >= 61:
            overall_rating = "GOOD"
        elif overall_score >= 41:
            overall_rating = "MODERATE"
        elif overall_score >= 21:
            overall_rating = "HIGH RISK"
        else:
            overall_rating = "CRITICAL RISK"

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(all_findings, key=lambda f: (sev_order.get(f.get("risk"), 5), conf_order.get(f.get("confidence"), 5)))
        top_findings = sorted_findings[:10]

        recent_assessments = scans[:5]

        return jsonify({
            "total_assets": total_assets,
            "active_assets": active_assets,
            "total_assessments": total_assessments,
            "total_findings": total_findings_count,
            "counts": counts,
            "overall_posture_score": overall_score,
            "overall_risk_rating": overall_rating,
            "top_findings": top_findings,
            "recent_assessments": recent_assessments
        })
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve dashboard metrics: {str(exc)}"}), 500

@app.get("/api/assets")
def api_assets():
    try:
        assets = get_all_assets_data()
        return jsonify(assets)
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve assets: {str(exc)}"}), 500

@app.get("/api/assets/<asset_id_or_ip>")
def api_asset_detail(asset_id_or_ip):
    try:
        assets = get_all_assets_data()
        for ast in assets:
            if ast["asset_id"] == asset_id_or_ip or ast["ip"] == asset_id_or_ip:
                return jsonify(ast)
        return jsonify({"error": f"Asset '{asset_id_or_ip}' not found."}), 404
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve asset details: {str(exc)}"}), 500

@app.get("/api/scans")
def api_scans():
    try:
        scans = load_scan_reports()
        return jsonify(scans)
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve scans: {str(exc)}"}), 500

@app.get("/api/scans/<assessment_id>")
def api_scan_detail(assessment_id):
    try:
        scans = load_scan_reports()
        for sc in scans:
            if sc["assessment_id"] == assessment_id:
                return jsonify(sc)
        return jsonify({"error": f"Assessment '{assessment_id}' not found."}), 404
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve scan details: {str(exc)}"}), 500

@app.get("/api/findings")
def api_findings():
    try:
        scans = load_scan_reports()
        all_findings = []
        for sc in scans:
            all_findings.extend(sc.get("findings", []))

        risk_filter = request.args.get("risk", "").strip().upper()
        conf_filter = request.args.get("confidence", "").strip().upper()
        service_filter = request.args.get("service", "").strip().lower()
        search_query = request.args.get("search", "").strip().lower()

        filtered = []
        for f in all_findings:
            if risk_filter and f.get("risk") != risk_filter:
                continue
            if conf_filter and f.get("confidence") != conf_filter:
                continue
            if service_filter and service_filter not in f.get("service", "").lower():
                continue
            if search_query:
                combined_text = f"{f.get('finding_id')} {f.get('title')} {f.get('target')} {f.get('ip')} {f.get('service')} {f.get('description')}".lower()
                if search_query not in combined_text:
                    continue
            filtered.append(f)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        filtered.sort(key=lambda f: (sev_order.get(f.get("risk"), 5), conf_order.get(f.get("confidence"), 5)))

        return jsonify(filtered)
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve findings: {str(exc)}"}), 500

@app.get("/api/findings/<finding_id>")
def api_finding_detail(finding_id):
    try:
        scans = load_scan_reports()
        for sc in scans:
            for f in sc.get("findings", []):
                if f.get("finding_id") == finding_id:
                    result = dict(f)
                    result["started_at"] = sc.get("started_at")
                    result["completed_at"] = sc.get("completed_at")
                    result["target_type"] = sc.get("target_type")
                    return jsonify(result)
        return jsonify({"error": f"Finding '{finding_id}' not found."}), 404
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve finding details: {str(exc)}"}), 500

@app.get("/api/reports")
def api_reports():
    try:
        reports_list = []
        
        # Scan JSON directory
        for p in list(REPORT_JSON_DIR.glob("*.json")) + list(REPORT_DIR.glob("*.json")):
            if not re.match(r"^(NetSecure_|scan_|discovery_)[A-Za-z0-9_\-]+\.json$", p.name):
                continue
            file_stat = p.stat()
            report_type = "Scan Assessment" if ("_NS-" in p.name or "scan_" in p.name) else "Network Discovery"
            
            report_id = p.stem.replace("NetSecure_", "").replace("scan_", "").replace("discovery_", "")
            target = "—"
            try:
                c = json.loads(p.read_text(encoding="utf-8"))
                if "report_metadata" in c:
                    report_id = c["report_metadata"].get("assessment_id", report_id)
                    target = c.get("assessment", {}).get("target") or c.get("discovery", {}).get("network") or "—"
                elif "assessment_id" in c:
                    report_id = c["assessment_id"]
                    target = c.get("target") or c.get("resolved_ip") or "—"
            except Exception:
                pass

            reports_list.append({
                "filename": p.name,
                "report_type": report_type,
                "report_id": report_id,
                "target": target,
                "created_at": datetime.fromtimestamp(file_stat.st_mtime).isoformat(timespec="seconds"),
                "file_size_bytes": file_stat.st_size,
                "format": "JSON",
                "download_url": f"/reports/json/{p.name}"
            })

        # Scan PDF directory
        for p in REPORT_PDF_DIR.glob("*.pdf"):
            if not re.match(r"^(NetSecure_|scan_|discovery_)[A-Za-z0-9_\-]+\.pdf$", p.name):
                continue
            file_stat = p.stat()
            report_type = "Scan Assessment" if ("_NS-" in p.name or "scan_" in p.name) else "Network Discovery"
            report_id = p.stem.replace("NetSecure_", "").replace("scan_", "").replace("discovery_", "")

            reports_list.append({
                "filename": p.name,
                "report_type": report_type,
                "report_id": report_id,
                "target": "—",
                "created_at": datetime.fromtimestamp(file_stat.st_mtime).isoformat(timespec="seconds"),
                "file_size_bytes": file_stat.st_size,
                "format": "PDF",
                "download_url": f"/reports/pdf/{p.name}"
            })

        reports_list.sort(key=lambda r: r["created_at"], reverse=True)
        return jsonify(reports_list)
    except Exception as exc:
        return jsonify({"error": f"Failed to list reports: {str(exc)}"}), 500

@app.get("/api/reports/<assessment_id>/json")
def api_get_report_json(assessment_id):
    if not re.match(r"^[A-Za-z0-9_\-]+$", assessment_id):
        return jsonify({"error": "Invalid assessment ID."}), 400

    scans = load_scan_reports()
    matching_scan = next((sc for sc in scans if sc["assessment_id"] == assessment_id), None)
    if not matching_scan:
        return jsonify({"error": f"Assessment '{assessment_id}' not found."}), 404

    json_path, json_file, payload = generate_json_report(matching_scan)
    return send_from_directory(REPORT_JSON_DIR, json_file, as_attachment=True)

@app.get("/api/reports/<assessment_id>/pdf")
def api_get_report_pdf(assessment_id):
    if not re.match(r"^[A-Za-z0-9_\-]+$", assessment_id):
        return jsonify({"error": "Invalid assessment ID."}), 400

    scans = load_scan_reports()
    matching_scan = next((sc for sc in scans if sc["assessment_id"] == assessment_id), None)
    if not matching_scan:
        return jsonify({"error": f"Assessment '{assessment_id}' not found."}), 404

    pdf_path, pdf_file = generate_pdf_report(matching_scan)
    return send_from_directory(REPORT_PDF_DIR, pdf_file, as_attachment=True)

@app.get("/reports/json/<filename>")
def get_reports_json(filename):
    if not re.match(r"^(NetSecure_|scan_|discovery_)[A-Za-z0-9_\-]+\.json$", filename):
        return jsonify({"error": "Invalid report filename."}), 400
    safe_path = (REPORT_JSON_DIR / filename).resolve()
    if not str(safe_path).startswith(str(REPORT_DIR.resolve())):
        return jsonify({"error": "Path traversal blocked."}), 403
    return send_from_directory(REPORT_JSON_DIR, filename, as_attachment=True)

@app.get("/reports/pdf/<filename>")
def get_reports_pdf(filename):
    if not re.match(r"^(NetSecure_|scan_|discovery_)[A-Za-z0-9_\-]+\.pdf$", filename):
        return jsonify({"error": "Invalid report filename."}), 400
    safe_path = (REPORT_PDF_DIR / filename).resolve()
    if not str(safe_path).startswith(str(REPORT_DIR.resolve())):
        return jsonify({"error": "Path traversal blocked."}), 403
    return send_from_directory(REPORT_PDF_DIR, filename, as_attachment=True)

@app.get("/reports/<filename>")
def reports_fallback(filename):
    if not re.match(r"^(NetSecure_|scan_|discovery_)[A-Za-z0-9_\-]+\.(json|pdf)$", filename):
        return jsonify({"error": "Invalid report filename format."}), 400

    if (REPORT_JSON_DIR / filename).exists():
        return send_from_directory(REPORT_JSON_DIR, filename, as_attachment=True)
    elif (REPORT_PDF_DIR / filename).exists():
        return send_from_directory(REPORT_PDF_DIR, filename, as_attachment=True)
    elif (REPORT_DIR / filename).exists():
        return send_from_directory(REPORT_DIR, filename, as_attachment=True)
    
    return jsonify({"error": "Report file not found."}), 404

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
