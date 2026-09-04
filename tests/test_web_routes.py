def test_full_scan_alert_incident_workflow(registered_client):
    # Run a real TPM inventory scan on this host
    resp = registered_client.post("/scan/run", data={}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Scan complete" in resp.data

    resp = registered_client.get("/logs")
    assert resp.status_code == 200

    resp = registered_client.get("/alerts")
    assert resp.status_code == 200

    resp = registered_client.get("/analytics/data")
    assert resp.status_code == 200
    assert resp.is_json

    resp = registered_client.get("/reports/export.csv")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={"alert_on_severity": "high"}, follow_redirects=True)
    assert b"Settings saved" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
