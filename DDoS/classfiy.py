import os
import pandas as pd

def add_label_column_from_filename(csv_path):

    # 1. Read the original CSV
    df = pd.read_csv(csv_path)

    # 2. Determine the type of traffic (attack or normal) based on the filename
    #    You can extend this mapping or use a series of if/elif... statements
    filename = os.path.basename(csv_path).lower()  # Extract filename and convert to lowercase for easier matching
    if "normal" in filename:
        label_value = "Normal"
    elif "syn" in filename:
        label_value = "SYN_Flood"
    elif "udp" in filename:
        label_value = "UDP_Flood"
    elif "icmp" in filename:
        label_value = "ICMP_Flood"
    elif "http" in filename:
        label_value = "HTTP_Flood"
    else:
        label_value = "Unclassified"

    # 3. Add the 'label' column
    df['label'] = label_value

    # 4. (Optional) Rename columns for easier feature processing later
    #    For example: Time -> timestamp, Source -> src_ip, Destination -> dst_ip, Length -> packet_len
    df = df.rename(columns={
        'Time': 'timestamp',
        'Source': 'src_ip',
        'Destination': 'dst_ip',
        'Protocol': 'protocol',
        'Length': 'packet_len',
        'Info': 'info'  # Keep or remove depending on your needs
    })

    # 5. Return the DataFrame; optionally, you could save it as a new CSV file here
    # df.to_csv("xxx_labeled.csv", index=False)
    return df


if __name__ == "__main__":
    # Assume a list of CSV files
    csv_files = [
        "C:/Users/ASUS/Desktop/normal traffic.csv",
        "C:/Users/ASUS/Desktop/tcp syn flood attack.csv",
        "C:/Users/ASUS/Desktop/UDP flood attack.csv",
        "C:/Users/ASUS/Desktop/ICMP attack.csv",
        "C:/Users/ASUS/Desktop/http flood attack.csv"
        # ...
    ]

    # Process each CSV, automatically adding a label column
    for f in csv_files:
        labeled_df = add_label_column_from_filename(f)
        print(f"File {f} labeled as '{labeled_df['label'].unique()[0]}'")
        print("First five rows:")
        print(labeled_df.head())
        print("-" * 50)

        # If you want to save the labeled file, specify the output path
        out_name = f.replace(".csv", "_labeled.csv")
        labeled_df.to_csv(out_name, index=False)
