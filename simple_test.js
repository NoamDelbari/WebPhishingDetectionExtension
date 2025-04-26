const puppeteer = require("puppeteer");
const path = require("path");
const fs = require("fs");
const csv = require("csv-parser");
const createCsvWriter = require("csv-writer").createObjectCsvWriter;
const express = require("express");

(async () => {
  // 1. Read the CSV file containing id, url, label
  const entries = [];
  const csvFilePath = path.resolve(
    "/Users/il021250/Desktop/cyber/data/",
    "phishing_dataset.csv"
  );

  fs.createReadStream(csvFilePath)
    .pipe(csv())
    .on("data", (row) => {
      // Expecting columns: id, url, label
      // e.g., row.id="0", row.url="http://example.com", row.label="phishing"
      entries.push({
        id: row.id,
        url: row.url,
        label: row.label,
      });
    })
    .on("end", async () => {
      console.log("CSV file successfully processed:", csvFilePath);

      // 2. Start a local HTTP server to serve the htmls/ directory
      const app = express();
      // Serve static files from the "htmls" folder at the root URL
      const htmlsDir = path.join(__dirname, "htmls");
      app.use(express.static(htmlsDir));

      const PORT = 3000;
      const server = app.listen(PORT, async () => {
        console.log(`Local server listening at http://localhost:${PORT}`);

        try {
          // 3. Launch Puppeteer with the extension loaded
          const extensionPath = path.resolve(__dirname, "SimpleExtension");
          const browser = await puppeteer.launch({
            headless: false, // needed for extension
            args: [
              `--disable-extensions-except=${extensionPath}`,
              `--load-extension=${extensionPath}`,
            ],
          });

          const results = [];
          // Let's just test the first 5 entries
          const firstFive = entries.slice(0, 1);

          for (const entry of firstFive) {
            // Instead of file://, we now use http://localhost:3000/<id>.html
            const localUrl = `http://localhost:${PORT}/${entry.id}.html`;
            console.log(
              `Processing entry id=${entry.id}, url=${localUrl}, label=${entry.label}`
            );

            const page = await browser.newPage();

            // Capture console messages and page errors
            page.on("console", (msg) => {
              console.log("PAGE LOG:", msg.type(), msg.text());
            });
            page.on("pageerror", (err) => {
              console.error("PAGE ERROR:", err);
            });

            try {
              await page.goto(localUrl, { waitUntil: "networkidle2" });
            } catch (error) {
              console.log(`Failed to load ${localUrl}:`, error);
              await page.close();
              continue;
            }

            // Wait a few seconds for the extension to run
            await new Promise((resolve) => setTimeout(resolve, 5000));

            // Evaluate to retrieve the extension's detection result
            const prediction = await page.evaluate(() => {
              return new Promise((resolve) => {
                function handler(event) {
                  if (event.data && event.data.__DEBUG__) {
                    console.log("PAGE LOG:", "debug", event.data.__DEBUG__);
                  }
                  if (event.data && event.data.type === "PREDICTION_RESULT") {
                    window.removeEventListener("message", handler);
                    resolve(event.data.prediction);
                  }
                }
                window.addEventListener("message", handler);
                window.postMessage({ type: "GET_PREDICTION" }, "*");
              });
            });
            
            results.push({
              url: entry.url,
              isURL: prediction.isURL,
              isContent: prediction.isContent,
              trueLabel: entry.label,
            });

            await page.close();
          }

          // Close the browser
          await browser.close();

          // 4. Write the detection results to detection_results.csv
          const csvWriter = createCsvWriter({
            path: "detection_results.csv",
            header: [
              { id: "url", title: "url" },
              { id: "isURL", title: "isURL" },
              { id: "isContent", title: "isContent" },
              { id: "trueLabel", title: "trueLabel" },
            ],
          });

          await csvWriter.writeRecords(results);
          console.log("Results written to detection_results.csv");
        } catch (err) {
          console.error("Error during test execution:", err);
        } finally {
          // 5. Shut down the local HTTP server
          server.close(() => {
            console.log("Local server closed.");
          });
        }
      });
    });
})();
