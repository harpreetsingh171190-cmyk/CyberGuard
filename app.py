"""CyberGuard local-first dashboard: provider lookups only; never visits submitted sites."""
import json
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from cyberguard_reputation import check_live_reputation, _validate_url
from history_db import save_scan, load_history, clear_history
from domain_lists import load_lists, save_lists, match_domain
from url_heuristics import analyze_url
from url_tools import defang_url, normalize_url, url_facts, url_fingerprint, extract_urls

load_dotenv()
st.set_page_config(page_title="CyberGuard URL Intelligence", page_icon="🛡️", layout="wide")
st.title("🛡️ CyberGuard URL Intelligence")
st.caption("Local-first threat triage · reputation APIs only · submitted websites are never opened")
with st.sidebar:
    st.header("Configuration")
    st.write("API keys are read from environment variables or a local `.env` file.")
    st.code("GOOGLE_SAFE_BROWSING_API_KEY=…\nVIRUSTOTAL_API_KEY=…", language="text")
    st.warning("Selected providers receive each URL, including path/query parameters. Do not submit confidential URLs.")
    providers=[]
    if st.checkbox("Google Safe Browsing", value=True): providers.append("google")
    if st.checkbox("VirusTotal existing report", value=True): providers.append("virustotal")
    st.caption("VirusTotal reads existing reports only; it does not submit scans.")

def scan_one(url):
    clean=_validate_url(url)
    match_kind, match_domain_value=match_domain(clean)
    result=check_live_reputation(clean, tuple(providers))
    result["domain_list_match"] = f"{match_kind}:{match_domain_value}" if match_kind else "none"
    result["heuristic_analysis"] = analyze_url(clean)
    if match_kind == "block": result["verdict"] = "LOCAL BLOCKLIST MATCH — REVIEW REQUIRED"
    save_scan(result, result["domain_list_match"])
    return result

def json_bytes(value): return json.dumps(value, indent=2, ensure_ascii=False).encode("utf-8")

def render_result(result):
    st.subheader(result["verdict"])
    heuristic = result.get("heuristic_analysis") or analyze_url(result.get("url", ""))
    c1, c2 = st.columns([1, 3])
    c1.metric("Offline heuristic risk", f"{heuristic['score']}/100", heuristic["level"])
    with c2:
        if heuristic["findings"]:
            st.write("**Why it was flagged**")
            st.dataframe(pd.DataFrame(heuristic["findings"]), use_container_width=True, hide_index=True)
        else:
            st.success("No configured URL-shape indicators were triggered.")
    with st.expander("URL structure details"):
        st.json(heuristic["components"])
    st.caption(heuristic["note"])
    if result.get("domain_list_match", "none") != "none": st.warning(f"Local domain list: {result['domain_list_match']}. Allowlisting is not proof of safety; blocklist matches require review.")
    cols=st.columns(max(1,len(result.get("provider_results",[]))))
    for col,item in zip(cols,result.get("provider_results",[])):
        with col:
            st.metric(item.get("provider","Provider"),item.get("status","unknown"))
            if item.get("last_analysis_stats"): st.json(item["last_analysis_stats"])
            if item.get("matches"): st.json(item["matches"])
            if item.get("message"): st.caption(item["message"])
    st.info(result.get("note","Treat results as decision support, not certainty."))
    st.download_button("Download JSON report",json_bytes(result),file_name="cyberguard_report.json",mime="application/json")

t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12=st.tabs(["Single URL","Batch CSV","Scan history","Domain lists & privacy","URL Structure Lab","IOC Toolkit","Incident Casebook","Rule-based Hunting","Email Header Analyzer","File Triage","Content Signatures","Campaign Clustering"])
with t1:
    url=st.text_input("URL to check",placeholder="https://example.com/path")
    if st.button("Check reputation",type="primary"):
        if not providers: st.error("Select at least one provider in the sidebar.")
        else:
            try:
                with st.spinner("Querying selected reputation providers…"): result=scan_one(url.strip())
                render_result(result)
            except Exception as e: st.error(f"Could not check URL: {e}")
with t2:
    st.write("Upload a CSV with a column named `url`. Requests are sequential to respect provider limits.")
    uploaded=st.file_uploader("CSV file",type=["csv"])
    if uploaded:
        try:
            df=pd.read_csv(uploaded)
            urlcol=next((c for c in df.columns if str(c).lower()=="url"),None)
            if urlcol is None: st.error("CSV must contain a column named `url`.")
            elif len(df)>500: st.error("Maximum 500 rows per upload.")
            elif st.button("Scan CSV",type="primary"):
                if not providers: st.error("Select at least one provider.")
                else:
                    rows=[]; progress=st.progress(0)
                    for i,value in enumerate(df[urlcol].fillna("").astype(str)):
                        row={"url":value,"verdict":"INVALID/UNSCANNED","provider_statuses":"","domain_list_match":"none","heuristic_score":"","heuristic_level":""}
                        try:
                            result=scan_one(value.strip()); row["verdict"]=result["verdict"]; row["domain_list_match"]=result["domain_list_match"]
                            row["heuristic_score"]=result["heuristic_analysis"]["score"]; row["heuristic_level"]=result["heuristic_analysis"]["level"]
                            row["provider_statuses"]="; ".join(f"{x.get('provider')}={x.get('status')}" for x in result["provider_results"])
                        except Exception as e: row["provider_statuses"]=str(e)[:180]
                        rows.append(row); progress.progress((i+1)/max(len(df),1))
                    out=pd.DataFrame(rows); st.dataframe(out,use_container_width=True)
                    st.download_button("Download batch CSV",out.to_csv(index=False).encode("utf-8-sig"),"cyberguard_batch_results.csv","text/csv")
        except Exception as e: st.error(f"Unable to read CSV: {e}")
with t3:
    history=load_history(500)
    if history:
        hdf=pd.DataFrame([{k:r[k] for k in ("id","scanned_at","url","verdict","list_match")} for r in history])
        total=len(history); threats=sum("THREAT" in r["verdict"] or "BLOCKLIST" in r["verdict"] for r in history)
        c1,c2,c3=st.columns(3); c1.metric("Saved scans",total); c2.metric("Threat/blocklist flags",threats); c3.metric("Inconclusive or other",total-threats)
        st.dataframe(hdf,use_container_width=True,hide_index=True)
        st.download_button("Export history CSV",hdf.to_csv(index=False).encode("utf-8-sig"),"cyberguard_history.csv","text/csv")
        st.divider()
        st.subheader("Threat hunting across saved scans")
        hunt_query = st.text_input("Search URL, hostname, verdict, or list match", key="hunt_query", placeholder="e.g. login or BLOCKLIST")
        hunt_verdicts = st.multiselect("Filter verdicts", sorted(hdf["verdict"].dropna().unique().tolist()), key="hunt_verdicts")
        filtered = hdf.copy()
        if hunt_query.strip():
            q = hunt_query.strip().casefold()
            filtered = filtered[filtered.astype(str).apply(lambda col: col.str.casefold().str.contains(q, regex=False)).any(axis=1)]
        if hunt_verdicts:
            filtered = filtered[filtered["verdict"].isin(hunt_verdicts)]
        st.caption(f"{len(filtered)} matching scan(s) out of {len(hdf)} loaded records.")
        st.dataframe(filtered, use_container_width=True, hide_index=True)
        st.download_button("Export filtered hunt results", filtered.to_csv(index=False).encode("utf-8-sig"), "cyberguard_hunt_results.csv", "text/csv")
        if st.button("Clear local history",type="secondary"):
            clear_history(); st.success("Local scan history cleared."); st.rerun()
    else: st.info("No saved scans yet. Results are stored in a local SQLite database.")
with t4:
    st.subheader("Local domain allowlist and blocklist")
    lists=load_lists()
    st.caption("Enter one hostname per line (e.g. example.com). Exact hosts and subdomains match. Blocklist matches flag for review; allowlist entries never override provider detections.")
    allow_text=st.text_area("Allowlist",value="\n".join(lists["allow"]),height=110)
    block_text=st.text_area("Blocklist",value="\n".join(lists["block"]),height=110)
    if st.button("Save domain lists"):
        try:
            new=save_lists({"allow":allow_text.splitlines(),"block":block_text.splitlines()}); st.success(f"Saved {len(new['allow'])} allowlist and {len(new['block'])} blocklist entries.")
        except ValueError as e: st.error(str(e))
    st.markdown("""
    **Privacy and limitations**
    - The app never fetches submitted target websites; it queries configured provider APIs only.
    - Local SQLite history stores full submitted URLs. Protect the database file and clear it when no longer needed.
    - API keys belong in environment variables or `.env`, never in source control.
    - Missing reports, no detections, and provider errors are not proof a URL is safe.
    - Allowlist is informational only and does not suppress provider warnings.
    - Use a secrets manager and access controls before multi-user/production deployment.
    """)

with t5:
    st.subheader("Offline URL structure analysis")
    st.write("Analyze suspicious URL patterns locally without calling Google Safe Browsing or VirusTotal. This is a heuristic triage aid, not a machine-learning prediction.")
    lab_url = st.text_input("URL for offline analysis", key="lab_url", placeholder="https://example.com/login")
    if st.button("Analyze URL structure"):
        try:
            clean = _validate_url(lab_url)
            analysis = analyze_url(clean)
            a, b = st.columns(2)
            a.metric("Heuristic score", f"{analysis['score']}/100")
            b.metric("Risk band", analysis["level"])
            st.json(analysis["components"])
            if analysis["findings"]:
                st.dataframe(pd.DataFrame(analysis["findings"]), use_container_width=True, hide_index=True)
            else:
                st.success("No configured URL-shape indicators were triggered.")
            st.caption(analysis["note"])
            st.download_button("Download analysis JSON", json_bytes({"url": clean, "heuristic_analysis": analysis}), "cyberguard_url_analysis.json", "application/json")
        except Exception as e:
            st.error(f"Could not analyze URL: {e}")


with t6:
    st.subheader("Incident-response utilities")
    st.write("Offline utilities for comparing URLs, sharing indicators safely, and exporting an IOC bundle. These tools do not visit submitted URLs or resolve DNS.")
    raw_iocs = st.text_area("URLs / indicators (one per line)", height=150, placeholder="https://example.com/login\nhttp://192.0.2.1/update")
    if st.button("Build IOC bundle", type="primary"):
        items=[]; seen=set(); invalid=[]
        for raw in raw_iocs.splitlines():
            raw=raw.strip()
            if not raw: continue
            try:
                clean=_validate_url(raw)
                norm=normalize_url(clean)
                if norm in seen: continue
                seen.add(norm)
                analysis=analyze_url(clean)
                items.append({"type":"url", "value":clean, "normalized":norm, "defanged":defang_url(clean), "facts":url_facts(clean), "heuristic_score":analysis["score"], "heuristic_level":analysis["level"], "findings":analysis["findings"], "sha256":url_fingerprint(clean)})
            except Exception as exc:
                invalid.append({"input":raw,"error":str(exc)[:160]})
        bundle={"schema":"cyberguard-ioc-bundle-v1", "note":"Heuristic triage only; not a confirmed threat verdict.", "unique_indicator_count":len(items), "indicators":items, "invalid_inputs":invalid}
        st.session_state["ioc_bundle"] = bundle
    bundle=st.session_state.get("ioc_bundle")
    if bundle:
        st.metric("Unique valid indicators", bundle["unique_indicator_count"])
        if bundle["indicators"]:
            st.dataframe(pd.DataFrame([{ "URL":x["value"], "Defanged":x["defanged"], "Risk score":x["heuristic_score"], "Risk band":x["heuristic_level"], "SHA-256":x["sha256"]} for x in bundle["indicators"]]), use_container_width=True, hide_index=True)
            st.download_button("Download IOC JSON bundle", json_bytes(bundle), "cyberguard_ioc_bundle.json", "application/json")
            defanged_text="\n".join(x["defanged"] for x in bundle["indicators"])
            st.text_area("Defanged indicators (safe for reports)", value=defanged_text, height=100)
            st.download_button("Download defanged TXT", defanged_text.encode("utf-8"), "cyberguard_defanged_iocs.txt", "text/plain")
        if bundle["invalid_inputs"]:
            st.warning(f"Skipped {len(bundle['invalid_inputs'])} invalid input(s).")
            st.dataframe(pd.DataFrame(bundle["invalid_inputs"]), use_container_width=True, hide_index=True)
    st.divider()
    st.subheader("Compare two URLs")
    left=st.text_input("First URL", key="compare_a", placeholder="https://example.com/a")
    right=st.text_input("Second URL", key="compare_b", placeholder="https://example.org/b")
    if st.button("Compare URL structure"):
        try:
            a=_validate_url(left); b=_validate_url(right)
            fa,fb=url_facts(a),url_facts(b)
            aa,ab=analyze_url(a),analyze_url(b)
            c1,c2=st.columns(2)
            with c1:
                st.markdown("**First URL**"); st.metric("Heuristic score", f"{aa['score']}/100", aa['level']); st.json(fa)
            with c2:
                st.markdown("**Second URL**"); st.metric("Heuristic score", f"{ab['score']}/100", ab['level']); st.json(fb)
            st.caption("Score difference is a comparison of configured URL-shape signals only; it does not establish which URL is malicious.")
        except Exception as exc: st.error(f"Comparison failed: {exc}")


with t6:
    st.divider()
    st.subheader("Extract URLs from text or logs")
    st.write("Paste an email, chat message, or log snippet. URL-like indicators are extracted offline; no URLs are opened.")
    source_text = st.text_area("Text / log content", key="ioc_source_text", height=140, placeholder="Suspicious link: hxxps://example[.]com/login")
    if st.button("Extract indicators"):
        # Support common defanged forms used in reports.
        prepared = source_text.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
        extracted = extract_urls(prepared)
        valid, rejected = [], []
        for candidate in extracted:
            try:
                clean = _validate_url(candidate)
                if normalize_url(clean) not in {x["normalized"] for x in valid}:
                    valid.append({"url": clean, "normalized": normalize_url(clean), "defanged": defang_url(clean), "sha256": url_fingerprint(clean), "risk": analyze_url(clean)["score"]})
            except Exception as exc:
                rejected.append({"candidate": candidate, "error": str(exc)[:120]})
        st.session_state["extracted_iocs"] = {"valid": valid, "rejected": rejected}
    extracted = st.session_state.get("extracted_iocs")
    if extracted is not None:
        st.metric("Unique URLs extracted", len(extracted["valid"]))
        if extracted["valid"]:
            st.dataframe(pd.DataFrame(extracted["valid"]), use_container_width=True, hide_index=True)
            st.download_button("Download extracted IOCs CSV", pd.DataFrame(extracted["valid"]).to_csv(index=False).encode("utf-8-sig"), "cyberguard_extracted_iocs.csv", "text/csv")
        if extracted["rejected"]:
            st.warning("Some URL-like strings were rejected by URL validation.")
            st.dataframe(pd.DataFrame(extracted["rejected"]), use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Campaign clustering & STIX 2.1 export")
    st.write("Group the current IOC bundle by a simple domain key and export portable STIX indicator objects. This is offline grouping, not attribution or a malware verdict.")
    from ioc_intelligence import cluster_indicators, to_stix_bundle
    current_bundle = st.session_state.get("ioc_bundle", {})
    current_indicators = current_bundle.get("indicators", [])
    if current_indicators:
        clusters = cluster_indicators(current_indicators)
        st.dataframe(pd.DataFrame([{ "Domain group (approx.)": g["group"], "Indicator count": g["count"], "Hosts": ", ".join(g["hosts"]), "Maximum heuristic score": g["max_risk"] } for g in clusters]), use_container_width=True, hide_index=True)
        st.caption("Domain grouping uses the final two hostname labels as a convenience heuristic; it is not Public Suffix List aware and must not be used for attribution.")
        st.download_button("Download STIX 2.1 bundle", json_bytes(to_stix_bundle(current_indicators)), "cyberguard_stix_bundle.json", "application/json")
    else:
        st.info("Build an IOC bundle above to enable clustering and STIX export.")


with t7:
    from casebook import load_cases, create_case, update_case, delete_case, STATUSES, SEVERITIES
    st.subheader("Local incident casebook")
    st.write("Create investigation cases, attach indicators, record analyst notes, and track status changes. Data stays in a local JSON file; protect it on shared devices.")
    cases = load_cases()
    cc1, cc2, cc3 = st.columns(3)
    cc1.metric("Total cases", len(cases))
    cc2.metric("Open cases", sum(c.get("status") not in {"Closed", "False positive"} for c in cases))
    cc3.metric("High / Critical", sum(c.get("severity") in {"High", "Critical"} for c in cases))
    with st.expander("Create a case", expanded=not bool(cases)):
        case_title = st.text_input("Case title", key="case_title")
        case_severity = st.selectbox("Severity", list(SEVERITIES), index=1, key="case_severity")
        existing_bundle = st.session_state.get("ioc_bundle", {})
        indicator_options = [x.get("value", "") for x in existing_bundle.get("indicators", []) if x.get("value")]
        selected_indicators = st.multiselect("Attach indicators from latest IOC bundle", indicator_options)
        case_notes = st.text_area("Initial analyst notes", key="case_notes")
        if st.button("Create incident case", type="primary"):
            try:
                created = create_case(case_title, case_severity, selected_indicators, case_notes)
                st.success(f"Created case {created['case_id']}")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not create case: {exc}")
    cases = load_cases()
    if cases:
        summary = pd.DataFrame([{ "Case ID": c.get("case_id"), "Title": c.get("title"), "Severity": c.get("severity"), "Status": c.get("status"), "Indicators": len(c.get("indicators", [])), "Updated": c.get("updated_at") } for c in cases])
        st.dataframe(summary, use_container_width=True, hide_index=True)
        st.download_button("Export casebook JSON", json_bytes(cases), "cyberguard_casebook.json", "application/json")
        st.download_button("Export case summary CSV", summary.to_csv(index=False).encode("utf-8-sig"), "cyberguard_case_summary.csv", "text/csv")
        selected_case_id = st.selectbox("Select case to update", [c["case_id"] for c in cases], format_func=lambda cid: next((f"{c['case_id']} — {c['title']}" for c in cases if c['case_id'] == cid), cid))
        chosen = next(c for c in cases if c["case_id"] == selected_case_id)
        with st.form("update_case_form"):
            new_status = st.selectbox("Status", list(STATUSES), index=list(STATUSES).index(chosen.get("status", "New")))
            new_severity = st.selectbox("Severity", list(SEVERITIES), index=list(SEVERITIES).index(chosen.get("severity", "Medium")))
            new_notes = st.text_area("Analyst notes", value=chosen.get("notes", ""), height=120)
            save_case = st.form_submit_button("Save case updates")
        if save_case:
            try:
                update_case(selected_case_id, new_status, new_severity, new_notes)
                st.success("Case updated.")
                st.rerun()
            except Exception as exc: st.error(f"Could not update case: {exc}")
        with st.expander("Case timeline and attached indicators"):
            st.json({"timeline": chosen.get("timeline", []), "indicators": chosen.get("indicators", [])})
        from analyst_report import build_case_report
        st.download_button("Export print-ready HTML incident report", build_case_report(chosen).encode("utf-8"), f"{selected_case_id}_incident_report.html", "text/html")
        st.caption("Open the HTML report in a browser and use Print → Save as PDF if a PDF copy is needed.")
        if st.button("Delete selected case", type="secondary"):
            try:
                delete_case(selected_case_id)
                st.success("Case deleted from local casebook.")
                st.rerun()
            except Exception as exc: st.error(f"Could not delete case: {exc}")
    else:
        st.info("No cases yet. Create a case to start an incident timeline.")
    st.caption("Casebook is local triage support, not a ticketing system. Back up exports securely and avoid storing secrets or sensitive full URLs in notes.")


with t8:
    from rules_engine import DEFAULT_RULES, scan_text, validate_rules
    st.subheader("Local rule-based text and log hunting")
    st.caption("Literal string matching only: imported rules are data, not executable code. No URLs are opened.")
    rules_text = st.text_area("Rules JSON", value=json.dumps(DEFAULT_RULES, indent=2), height=240, key="hunting_rules_json")
    hunting_text = st.text_area("Paste email text, logs, alerts, or threat notes", height=220, placeholder="Paste text to inspect locally…")
    if st.button("Hunt for indicators", type="primary"):
        try:
            custom_rules = validate_rules(json.loads(rules_text))
            hunting_result = scan_text(hunting_text, custom_rules)
            st.session_state["hunting_result"] = hunting_result
        except (ValueError, json.JSONDecodeError) as exc:
            st.error(f"Rules JSON is invalid: {exc}")
    hunting_result = st.session_state.get("hunting_result")
    if hunting_result:
        h1, h2, h3 = st.columns(3)
        h1.metric("Matched rules", hunting_result["matched_rules"])
        h2.metric("Highest severity", hunting_result["max_severity"].title())
        h3.metric("Characters scanned", hunting_result["text_characters_scanned"])
        if hunting_result["findings"]:
            st.dataframe(pd.DataFrame(hunting_result["findings"]), use_container_width=True, hide_index=True)
        else:
            st.success("No configured literal rules matched the supplied text.")
        st.download_button("Download hunting results JSON", json_bytes(hunting_result), "cyberguard_hunting_results.json", "application/json")
        st.caption(hunting_result["note"])


with t9:
    from email_header_analyzer import analyze_email_headers
    st.subheader("Offline email-header phishing triage")
    st.caption("Paste raw headers only. This analysis is local and does not send or fetch the email.")
    raw_headers = st.text_area("Raw email headers", height=240, placeholder="From: ...\nReply-To: ...\nAuthentication-Results: ...\nReceived: ...", key="email_header_text")
    if st.button("Analyze email headers", type="primary"):
        st.session_state["email_header_result"] = analyze_email_headers(raw_headers)
    email_result = st.session_state.get("email_header_result")
    if email_result:
        ec1, ec2, ec3 = st.columns(3)
        ec1.metric("Findings", email_result["finding_count"])
        ec2.metric("Highest severity", email_result["highest_severity"].title())
        ec3.metric("Received hops", email_result["received_hops"])
        st.json({k: v for k, v in email_result.items() if k != "note"})
        if email_result["findings"]:
            st.dataframe(pd.DataFrame(email_result["findings"]), use_container_width=True, hide_index=True)
        st.download_button("Download header analysis JSON", json_bytes(email_result), "cyberguard_email_header_analysis.json", "application/json")
        st.warning(email_result["note"])


with t10:
    from file_triage import analyze_file_bytes
    st.subheader("Offline file triage")
    st.caption("Static analysis only: the uploaded file is not executed, extracted, or sent to a reputation provider.")
    file_upload = st.file_uploader("Choose a file for static triage", key="static_file_triage")
    if file_upload is not None:
        if file_upload.size > 100 * 1024 * 1024:
            st.error("Maximum supported file size is 100 MiB.")
        elif st.button("Analyze file safely", type="primary"):
            file_result = analyze_file_bytes(file_upload.name, file_upload.getvalue())
            st.session_state["file_triage_result"] = file_result
    file_result = st.session_state.get("file_triage_result")
    if file_result:
        fc1, fc2, fc3 = st.columns(3)
        fc1.metric("Size", f"{file_result['size_bytes']:,} bytes")
        fc2.metric("Detected type", file_result["detected_type"])
        fc3.metric("Highest severity", file_result["highest_severity"].title())
        st.code(file_result["sha256"], language="text")
        st.write(f"SHA-256: **{file_result['sha256']}**")
        if file_result["findings"]:
            st.dataframe(pd.DataFrame(file_result["findings"]), use_container_width=True, hide_index=True)
        else:
            st.success("No configured static indicators were found.")
        st.download_button("Download file triage JSON", json_bytes(file_result), "cyberguard_file_triage.json", "application/json")
        st.warning(file_result["note"])


with t11:
    from content_signatures import scan_content, DEFAULT_SIGNATURES
    st.subheader("Offline content-signature scanner")
    st.caption("Bounded static pattern matching only; files are never executed or extracted. Scans at most the first 2 MiB.")
    content_upload = st.file_uploader("Upload a text, script, or other file for signature scanning", key="content_signature_upload")
    if content_upload is not None:
        if content_upload.size > 100 * 1024 * 1024:
            st.error("Maximum upload size is 100 MiB.")
        elif st.button("Scan content signatures", type="primary"):
            st.session_state["content_signature_result"] = scan_content(content_upload.name, content_upload.getvalue())
    sig_result = st.session_state.get("content_signature_result")
    if sig_result:
        sc1, sc2, sc3 = st.columns(3)
        sc1.metric("Matches", sig_result["finding_count"])
        sc2.metric("Highest severity", sig_result["highest_severity"].title())
        sc3.metric("Bytes scanned", f"{sig_result['bytes_scanned']:,}")
        st.code(sig_result["sha256"], language="text")
        if sig_result["findings"]:
            st.dataframe(pd.DataFrame(sig_result["findings"]), use_container_width=True, hide_index=True)
        else:
            st.success("No configured content signatures matched.")
        st.download_button("Download signature findings JSON", json_bytes(sig_result), "cyberguard_content_signatures.json", "application/json")
        st.warning(sig_result["note"])


with t12:
    from campaign_clustering import cluster_indicators
    st.subheader("Offline IOC campaign clustering")
    st.caption("Find repeated hosts, similar-looking hostnames, and shared path prefixes. No DNS lookups or websites are contacted.")
    cluster_text = st.text_area("Paste URLs (one per line)", key="campaign_urls", height=180, placeholder="https://paypa1.example/login\nhttps://paypal.example/login\nhttps://sample.invalid/account")
    threshold = st.slider("Hostname similarity threshold", min_value=0.50, max_value=1.00, value=0.78, step=0.01)
    if st.button("Cluster indicators", type="primary"):
        accepted, rejected = [], []
        for raw in cluster_text.splitlines():
            raw = raw.strip()
            if not raw: continue
            try: accepted.append(_validate_url(raw))
            except Exception as exc: rejected.append({"input": raw, "error": str(exc)[:120]})
        result = cluster_indicators(accepted, threshold)
        result["rejected_inputs"] = rejected
        st.session_state["campaign_cluster_result"] = result
    result = st.session_state.get("campaign_cluster_result")
    if result:
        c1, c2, c3 = st.columns(3)
        c1.metric("Valid unique URLs", result["indicator_count"])
        c2.metric("Unique hosts", result["unique_host_count"])
        c3.metric("Similar-host pairs", len(result["similar_hostname_pairs"]))
        if result["hosts"]: st.dataframe(pd.DataFrame(result["hosts"]), use_container_width=True, hide_index=True)
        st.markdown("**Potentially similar hostnames**")
        if result["similar_hostname_pairs"]: st.dataframe(pd.DataFrame(result["similar_hostname_pairs"]), use_container_width=True, hide_index=True)
        else: st.info("No hostname pairs met the selected threshold.")
        st.markdown("**Shared URL path prefixes**")
        if result["shared_path_prefix_groups"]: st.dataframe(pd.DataFrame(result["shared_path_prefix_groups"]), use_container_width=True, hide_index=True)
        else: st.caption("No repeated first path segments found.")
        if result["rejected_inputs"]: st.warning(f"Rejected {len(result['rejected_inputs'])} invalid URL(s).")
        st.download_button("Download campaign clustering JSON", json_bytes(result), "cyberguard_campaign_clusters.json", "application/json")
        st.warning(result["note"])
