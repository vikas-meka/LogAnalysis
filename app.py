import csv
import re
import pandas as pd
import streamlit as st

def parse_log_line(line):
    parts = re.split(r"\s+", line.strip())
    if len(parts) < 9:
        return None, None
    ip_address = parts[0]
    request = parts[5] + " " + parts[6]
    return ip_address, request

def analyze_log(log_content):
    ip_counts = {}
    endpoint_counts = {}
    suspicious_ips = {}

    for line in log_content.splitlines():
        line = line.strip()
        if not line:
            continue

        ip_address, request = parse_log_line(line)

        if ip_address is None or request is None:
            continue

        endpoint = request.split()[1]
        ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1
        endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1

        if "401" in line and "Invalid credentials" in line:
            suspicious_ips[ip_address] = suspicious_ips.get(ip_address, 0) + 1

    return ip_counts, endpoint_counts, suspicious_ips

def save_results_to_csv(ip_counts, endpoint_counts, suspicious_ips):
    output = []

    output.append(["IP Address", "Request Count"])
    if ip_counts:
        for ip, count in ip_counts.items():
            output.append([ip, count])
    else:
        output.append(["No IP counts available."])

    output.append([])

    output.append(["Endpoint", "Access Count"])
    if endpoint_counts:
        sorted_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:1]
        for endpoint, count in sorted_endpoints:
            output.append([endpoint, count])
    else:
        output.append(["No endpoints accessed."])

    output.append([])

    output.append(["IP Address", "Failed Login Count"])
    if suspicious_ips:
        high_suspicious_ips = {ip: count for ip, count in suspicious_ips.items() if count > 10}
        if high_suspicious_ips:
            sorted_suspicious = sorted(high_suspicious_ips.items(), key=lambda x: x[1], reverse=True)[:1]
            for ip, count in sorted_suspicious:
                output.append([ip, count])
        else:
            output.append(["No suspicious IPs detected above the threshold."])
    else:
        output.append(["No suspicious IPs detected."])

    return output

def main():
    st.title("Log File Analysis")

    uploaded_file = st.file_uploader("Upload a log file", type=["log", "txt"])

    if uploaded_file is not None:
        try:
            log_content = uploaded_file.getvalue().decode("utf-8")
            ip_counts, endpoint_counts, suspicious_ips = analyze_log(log_content)

            st.subheader("IP Counts:")
            if ip_counts:
                ip_df = pd.DataFrame(ip_counts.items(), columns=["IP Address", "Request Count"])
                st.table(ip_df)
            else:
                st.write("No IP counts available.")

            st.subheader("\nMost Frequently Accessed Endpoint:")
            if endpoint_counts:
                sorted_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:1]
                top_endpoint = sorted_endpoints[0]
                st.write(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")
            else:
                st.write("No endpoints accessed.")

            st.subheader("\nSuspicious Activity Detected:")
            if suspicious_ips:
                high_suspicious_ips = {ip: count for ip, count in suspicious_ips.items() if count > 10}
                if high_suspicious_ips:
                    sorted_suspicious = sorted(high_suspicious_ips.items(), key=lambda x: x[1], reverse=True)[:1]
                    suspicious_df = pd.DataFrame(sorted_suspicious, columns=["IP Address", "Failed Login Count"])
                    st.table(suspicious_df)
                else:
                    st.write("No suspicious IPs detected above the threshold.")
            else:
                st.write("No suspicious IPs detected.")

            csv_data = save_results_to_csv(ip_counts, endpoint_counts, suspicious_ips)
            csv_string = "\n".join([",".join(map(str, row)) for row in csv_data])
            st.download_button("Download CSV", csv_string, file_name="log_analysis_results.csv", mime="text/csv")

        except FileNotFoundError:
            st.error(f"Error: The file '{uploaded_file.name}' was not found.")
        except Exception as e:
            st.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
