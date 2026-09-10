"""Charter Condition 6 support: analyze_live_runtime against GetAgentRuntime shapes.

The real live run is captured in references/live_cloud_posture_verified.md; these
tests lock the analyzer's pass/fail logic against the response shape."""

from agentaudit.layers.cloud_posture import analyze_live_runtime, check_live_runtime

# Verbatim shape of the real GetAgentRuntime response (see the references doc).
REAL_RESPONSE = {
    "agentRuntimeId": "agentauditdeploy-tvmm505Sjc",
    "agentRuntimeVersion": "7",
    "status": "READY",
    "roleArn": "arn:aws:iam::580912381651:role/AmazonBedrockAgentCoreSDKRuntime-eu-north-1-aebece9071",
    "networkConfiguration": {"networkMode": "PUBLIC"},
    "metadataConfiguration": {"requireMMDSV2": True},
    "protocolConfiguration": {"serverProtocol": "HTTP"},
}


def test_public_network_mode_is_flagged():
    findings = analyze_live_runtime(REAL_RESPONSE, "agentcore-runtime://x")
    dets = {f.detector for f in findings}
    assert "runtime-network-mode" in dets
    nm = next(f for f in findings if f.detector == "runtime-network-mode")
    assert nm.severity.value == "medium"
    assert "PUBLIC" in nm.evidence


def test_imdsv2_required_is_not_flagged():
    findings = analyze_live_runtime(REAL_RESPONSE, "src")
    assert "runtime-imdsv2" not in {f.detector for f in findings}


def test_imdsv1_allowed_is_flagged_high():
    resp = dict(REAL_RESPONSE, metadataConfiguration={"requireMMDSV2": False})
    findings = analyze_live_runtime(resp, "src")
    hit = [f for f in findings if f.detector == "runtime-imdsv2"]
    assert len(hit) == 1 and hit[0].severity.value == "high"


def test_vpc_mode_and_imdsv2_is_a_clean_pass():
    resp = {
        "networkConfiguration": {"networkMode": "VPC"},
        "metadataConfiguration": {"requireMMDSV2": True},
    }
    assert analyze_live_runtime(resp, "src") == []


def test_memory_without_encryption_is_flagged():
    resp = dict(REAL_RESPONSE, memoryConfiguration={"eventExpiryDuration": None})
    dets = {f.detector for f in analyze_live_runtime(resp, "src")}
    assert "memory-encryption-ttl" in dets


class _FakeCP:
    def __init__(self, resp):
        self._resp = resp

    def get_agent_runtime(self, agentRuntimeId):  # noqa: N803
        assert agentRuntimeId == "rt-1"
        return self._resp


def test_check_live_runtime_returns_raw_and_findings():
    findings, raw = check_live_runtime("rt-1", cp_client=_FakeCP(REAL_RESPONSE))
    assert "get_agent_runtime" in raw
    assert raw["get_agent_runtime"]["networkConfiguration"]["networkMode"] == "PUBLIC"
    assert any(f.detector == "runtime-network-mode" for f in findings)
