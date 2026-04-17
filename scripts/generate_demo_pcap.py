from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap


SERVER_IP = "192.168.56.10"
SERVER_PORT = 80
OUTPUT_FILE = Path("data/raw/demo_http_capture.pcap")


def build_http_request(method: str, path: str, host: str, user_agent: str) -> bytes:
    request = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: */*",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(request).encode("utf-8")


def build_http_response(status_code: int) -> bytes:
    reason_map = {
        200: "OK",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
    }
    reason = reason_map.get(status_code, "OK")
    body = f"status={status_code}\n"
    response = [
        f"HTTP/1.1 {status_code} {reason}",
        "Server: aegis-demo",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "",
        body,
    ]
    return "\r\n".join(response).encode("utf-8")


def add_conversation(packets: list, timestamp: float, client_ip: str, client_port: int, method: str, path: str, status: int, host: str, user_agent: str):
    seq_client = 1000 + client_port
    seq_server = 5000 + client_port

    syn = IP(src=client_ip, dst=SERVER_IP) / TCP(sport=client_port, dport=SERVER_PORT, flags="S", seq=seq_client)
    syn.time = timestamp
    packets.append(syn)

    syn_ack = IP(src=SERVER_IP, dst=client_ip) / TCP(sport=SERVER_PORT, dport=client_port, flags="SA", seq=seq_server, ack=seq_client + 1)
    syn_ack.time = timestamp + 0.001
    packets.append(syn_ack)

    ack = IP(src=client_ip, dst=SERVER_IP) / TCP(sport=client_port, dport=SERVER_PORT, flags="A", seq=seq_client + 1, ack=seq_server + 1)
    ack.time = timestamp + 0.002
    packets.append(ack)

    request_payload = build_http_request(method, path, host, user_agent)
    request = (
        IP(src=client_ip, dst=SERVER_IP)
        / TCP(sport=client_port, dport=SERVER_PORT, flags="PA", seq=seq_client + 1, ack=seq_server + 1)
        / Raw(load=request_payload)
    )
    request.time = timestamp + 0.003
    packets.append(request)

    request_ack = IP(src=SERVER_IP, dst=client_ip) / TCP(
        sport=SERVER_PORT,
        dport=client_port,
        flags="A",
        seq=seq_server + 1,
        ack=seq_client + 1 + len(request_payload),
    )
    request_ack.time = timestamp + 0.004
    packets.append(request_ack)

    response_payload = build_http_response(status)
    response = (
        IP(src=SERVER_IP, dst=client_ip)
        / TCP(
            sport=SERVER_PORT,
            dport=client_port,
            flags="PA",
            seq=seq_server + 1,
            ack=seq_client + 1 + len(request_payload),
        )
        / Raw(load=response_payload)
    )
    response.time = timestamp + 0.005
    packets.append(response)

    response_ack = IP(src=client_ip, dst=SERVER_IP) / TCP(
        sport=client_port,
        dport=SERVER_PORT,
        flags="A",
        seq=seq_client + 1 + len(request_payload),
        ack=seq_server + 1 + len(response_payload),
    )
    response_ack.time = timestamp + 0.006
    packets.append(response_ack)


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    conversations = [
        (1713345300.100, "10.0.14.23", 41001, "GET", "/", 200, "shop.internal", "Mozilla/5.0"),
        (1713345302.500, "10.0.14.23", 41002, "GET", "/search?q=ergonomic+keyboard", 200, "shop.internal", "Mozilla/5.0"),
        (1713345304.200, "185.231.154.21", 43001, "GET", "/search?q=%27%20OR%201%3D1%20--", 500, "shop.internal", "sqlmap/1.8.3"),
        (1713345304.900, "185.231.154.21", 43002, "GET", "/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 500, "shop.internal", "sqlmap/1.8.3"),
        (1713345305.600, "185.231.154.21", 43003, "GET", "/search?q=%27%20AND%20SLEEP(5)%20--", 500, "shop.internal", "sqlmap/1.8.3"),
        (1713345308.300, "103.77.192.8", 44001, "GET", "/robots.txt", 404, "shop.internal", "Nmap Scripting Engine"),
        (1713345308.700, "103.77.192.8", 44002, "GET", "/.env", 404, "shop.internal", "Nmap Scripting Engine"),
        (1713345309.100, "103.77.192.8", 44003, "GET", "/phpmyadmin", 404, "shop.internal", "Nmap Scripting Engine"),
        (1713345309.500, "103.77.192.8", 44004, "GET", "/.git/config", 404, "shop.internal", "Nmap Scripting Engine"),
        (1713345309.900, "103.77.192.8", 44005, "GET", "/server-status", 403, "shop.internal", "Nmap Scripting Engine"),
        (1713345310.700, "172.16.10.44", 45001, "GET", "/checkout", 200, "shop.internal", "Mozilla/5.0"),
    ]

    packets = []
    for conversation in conversations:
        add_conversation(packets, *conversation)

    wrpcap(str(OUTPUT_FILE), packets)
    print(f"Wrote {len(packets)} packets to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
