from ai.intent_parser import IntentParser


def test_network_scan_is_parsed():
    result = IntentParser().parse(
        "scan 192.168.1.10 port 80,443"
    )

    assert result.action == "network_scan"
    assert result.tool == "nmap"
    assert result.target == "192.168.1.10"
    assert result.ports == [80, 443]


def test_unknown_request_does_not_create_tool():
    result = IntentParser().parse(
        "tell me something interesting"
    )

    assert result.action == "unknown"
    assert result.tool is None
    assert result.target is None


def test_empty_request_is_not_executable():
    result = IntentParser().parse("")

    assert result.action == "unknown"
    assert result.tool is None


def test_parser_does_not_execute_commands():
    result = IntentParser().parse(
        "scan 192.168.1.10"
    )

    # Parsing produces data only.
    # It must never execute the requested tool.
    assert result.tool == "nmap"
