package com.secure.audit.service;
import com.secure.audit.model.ScanResponse;
import com.secure.audit.model.Vulnerability;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
@Slf4j
public class HtmlReportService {

    private static final String REPORT_DIR =
            "reports";

    public String generateReport(
            ScanResponse scanResponse
    ) {

        try {

            Files.createDirectories(
                    Paths.get(REPORT_DIR)
            );

            String fileName =
                    "scan-report-"
                            + System.currentTimeMillis()
                            + ".html";

            Path reportPath =
                    Paths.get(REPORT_DIR, fileName);

            String html =
                    buildHtml(scanResponse);

            Files.writeString(reportPath, html);

            log.info(
                    "HTML report generated at: {}",
                    reportPath
            );

            return reportPath.toString();

        } catch (Exception e) {

            throw new RuntimeException(
                    "Failed to generate HTML report"
            );
        }
    }

    private String buildHtml(
            ScanResponse response
    ) {

        StringBuilder findingsRows =
                new StringBuilder();

        for (Vulnerability vulnerability
                : response.getFindings()) {

            findingsRows.append("""
                    <tr>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                    </tr>
                    """.formatted(
                    vulnerability.getScanner(),
                    vulnerability.getSeverity(),
                    vulnerability.getType(),
                    vulnerability.getFile(),
                    vulnerability.getLine(),
                    vulnerability.getMessage()
            ));
        }

        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Security Scan Report</title>

                    <style>

                        body {
                            font-family: Arial;
                            margin: 40px;
                            background-color: #f4f6f8;
                        }

                        h1 {
                            color: #333;
                        }

                        .summary {
                            display: flex;
                            gap: 20px;
                            margin-bottom: 30px;
                        }

                        .card {
                            padding: 20px;
                            border-radius: 10px;
                            color: white;
                            width: 150px;
                            text-align: center;
                            font-size: 20px;
                        }

                        .critical {
                            background-color: #d32f2f;
                        }

                        .high {
                            background-color: #f57c00;
                        }

                        .medium {
                            background-color: #fbc02d;
                            color: black;
                        }

                        .low {
                            background-color: #388e3c;
                        }

                        table {
                            width: 100%%;
                            border-collapse: collapse;
                            background: white;
                        }

                        th, td {
                            border: 1px solid #ddd;
                            padding: 12px;
                            text-align: left;
                        }

                        th {
                            background-color: #1976d2;
                            color: white;
                        }

                        tr:nth-child(even) {
                            background-color: #f2f2f2;
                        }

                    </style>
                </head>

                <body>

                    <h1>Security Scan Report</h1>

                    <div class="summary">

                        <div class="card critical">
                            Critical<br>
                            %d
                        </div>

                        <div class="card high">
                            High<br>
                            %d
                        </div>

                        <div class="card medium">
                            Medium<br>
                            %d
                        </div>

                        <div class="card low">
                            Low<br>
                            %d
                        </div>

                    </div>

                    <h2>
                        Total Findings: %d
                    </h2>

                    <table>

                        <tr>
                            <th>Scanner</th>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Message</th>
                        </tr>

                        %s

                    </table>

                </body>
                </html>
                """.formatted(
                response.getCritical(),
                response.getHigh(),
                response.getMedium(),
                response.getLow(),
                response.getTotalFindings(),
                findingsRows
        );
    }
}