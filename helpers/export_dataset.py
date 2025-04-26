import sys
import os
import pickle
import csv

# Adjust your import according to how htmldom is structured in your environment
# from htmldom.htmldom import HtmlDom  # If needed, depending on your htmldom version

def main():
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <input_pickle> <output_csv>")
        sys.exit(1)

    pickle_path = sys.argv[1]
    csv_path = sys.argv[2]

    # 1) Load the pickled dataset
    with open(pickle_path, 'rb') as f:
        dataset = pickle.load(f)

    print(f"Loaded {len(dataset)} entries from '{pickle_path}'")

    # 2) Prepare to write CSV
    # Columns: id, url, label
    with open(csv_path, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["id", "url", "label"])  # header row

        # Ensure "htmls" directory exists
        os.makedirs("htmls", exist_ok=True)

        # 3) Iterate through each item in the dataset
        for i, (url, record) in enumerate(dataset.items()):
            # a) Extract the label (i.e. "status")
            label = record.get("status", "N/A")

            # b) Write row to CSV
            writer.writerow([i, url, label])

            # Adjust these lines exactly as requested:
            dom_object = record['dom']
            # Some versions require calling createDom(), but we'll follow the snippet exactly:

            # The user snippet references "dom_object.dom_object"
            # to find <html> nodes:
            all_elements = dom_object.find("html")
            # Then convert that find() result to a string
            html_content = str(all_elements.html())

            # d) Save to a file named i.html
            output_html_path = os.path.join("htmls", f"{i}.html")
            with open(output_html_path, 'w', encoding='utf-8') as html_file:
                html_file.write(html_content)

    print(f"CSV saved to '{csv_path}', HTML files saved in 'htmls/' directory.")

if __name__ == "__main__":
    main()
