const scanButton =
    document.getElementById("scanButton");

scanButton.addEventListener(
    "click",
    async () => {

        const fileInput =
            document.getElementById("zipFile");

        const file =
            fileInput.files[0];

        if (!file) {

            alert("Please select a ZIP file");

            return;
        }

        document
            .getElementById("loading")
            .classList.remove("hidden");

        const formData =
            new FormData();

        formData.append("file", file);

        try {

            const response =
                await fetch("/api/scans", {

                    method: "POST",

                    body: formData
                });

            const data =
                await response.json();

            renderResults(data);

        } catch (error) {

            alert("Scan failed");

            console.error(error);

        } finally {

            document
                .getElementById("loading")
                .classList.add("hidden");
        }
    }
);

function renderResults(data) {
const reportSection =
    document.getElementById(
        "reportSection"
    );

reportSection.classList.remove(
    "hidden"
);

const reportLink =
    document.getElementById(
        "reportLink"
    );

reportLink.href =
    "/" + data.reportPath
            .replaceAll("\\\\", "/");

    document
        .getElementById("results")
        .classList.remove("hidden");

    document
        .getElementById("criticalCount")
        .innerText = data.critical;

    document
        .getElementById("highCount")
        .innerText = data.high;

    document
        .getElementById("mediumCount")
        .innerText = data.medium;

    document
        .getElementById("lowCount")
        .innerText = data.low;

    const table =
        document.getElementById("findingsTable");

    table.innerHTML = "";

    data.findings.forEach(finding => {

        const row =
            `
            <tr>
                <td>${finding.scanner}</td>
                <td>${finding.severity}</td>
                <td>${finding.type}</td>
                <td>${finding.file}</td>
                <td>${finding.line}</td>
            </tr>
            `;

        table.innerHTML += row;
    });
}