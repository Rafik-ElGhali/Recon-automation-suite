import shodan

def shodan_lookup(ip, api_key):
    """
    Queries Shodan for all available data on a given IP.
    Returns a dict with org, os, country, ports, and banners.
    """
    api = shodan.Shodan(api_key)

    try:
        result = api.host(ip)

        data = {
            "ip":      result.get("ip_str", ip),
            "org":     result.get("org", "N/A"),
            "os":      result.get("os", "N/A"),
            "country": result.get("country_name", "N/A"),
            "ports":   result.get("ports", []),
            "banners": []
        }

        for service in result.get("data", []):
            banner_entry = {
                "port":      service.get("port"),
                "transport": service.get("transport", "tcp"),
                "banner":    service.get("data", "").strip()[:200]
            }
            data["banners"].append(banner_entry)

        return data

    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None


def print_results(data):
    if not data:
        return

    print(f"\n{'='*50}")
    print(f"  Shodan Report — {data['ip']}")
    print(f"{'='*50}")
    print(f"  Organisation : {data['org']}")
    print(f"  OS           : {data['os']}")
    print(f"  Country      : {data['country']}")
    print(f"  Open Ports   : {', '.join(str(p) for p in sorted(data['ports']))}")
    print(f"\n  --- Banners ---")

    for b in data["banners"]:
        print(f"\n  [Port {b['port']}/{b['transport']}]")
        first_line = b["banner"].splitlines()[0] if b["banner"] else "No banner"
        print(f"  {first_line}")

    print(f"\n{'='*50}")


def main():
    import os
    API_KEY = os.environ.get("SHODAN_API_KEY", "YOUR_SHODAN_API_KEY_HERE")
    ip      = "45.33.32.156"  # scanme.nmap.org

    print(f"[*] Querying Shodan for {ip}...")
    data = shodan_lookup(ip, API_KEY)
    print_results(data)


if __name__ == "__main__":
    main()