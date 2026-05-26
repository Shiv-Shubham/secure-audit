package com.secure.audit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.audit.dto.semgrep.SemgrepResponse;
import com.secure.audit.dto.semgrep.SemgrepResult;
import com.secure.audit.model.Vulnerability;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class SemgrepScannerService {

    private final ObjectMapper objectMapper;

    public List<Vulnerability> runSemgrepScan(Path projectPath) {

        try {

            ProcessBuilder processBuilder = new ProcessBuilder(
                    "semgrep",
                    "scan",
                    "--config",
                    "auto",
                    "--json",
                    "--quiet",
                    projectPath.toString()
            );

            Process process = processBuilder.start();

            StringBuilder output = new StringBuilder();

            try (BufferedReader reader =
                         new BufferedReader(
                                 new InputStreamReader(
                                         process.getInputStream()
                                 )
                         )) {

                String line;

                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }

            int exitCode = process.waitFor();

            log.info("Semgrep finished with exit code: {}", exitCode);

            SemgrepResponse semgrepResponse =
                    objectMapper.readValue(
                            output.toString(),
                            SemgrepResponse.class
                    );

            return mapToVulnerabilities(
                    semgrepResponse.getResults()
            );

        } catch (Exception e) {

            log.error("Error while running Semgrep", e);

            throw new RuntimeException("Semgrep scan failed");
        }
    }

    private List<Vulnerability> mapToVulnerabilities(
            List<SemgrepResult> results
    ) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (results == null) {
            return vulnerabilities;
        }

        for (SemgrepResult result : results) {

            vulnerabilities.add(
                    Vulnerability.builder()
                            .type(result.getCheck_id())
                            .severity(
                                    mapSeverity(
                                            result.getExtra().getSeverity()
                                    )
                            )
                            .file(result.getPath())
                            .line(result.getStart().getLine())
                            .message(
                                    result.getExtra().getMessage()
                            )
                            .scanner("Semgrep")
                            .build()
            );
        }

        return vulnerabilities;
    }

    private String mapSeverity(String severity) {

        if (severity == null) {
            return "MEDIUM";
        }

        return switch (severity.toUpperCase()) {

            case "ERROR" -> "HIGH";

            case "WARNING" -> "MEDIUM";

            case "INFO" -> "LOW";

            default -> "MEDIUM";
        };
    }
//    private String cleanFilePath(String fullPath) {
//
//        String normalized =
//                fullPath.replace("\\", "/");
//
//        log.info("Original path: {}", normalized);
//
//        String marker = "/extracted/";
//
//        int extractedIndex = normalized.indexOf(marker);
//
//        if (extractedIndex != -1) {
//
//            String cleaned = normalized.substring(
//                    extractedIndex + marker.length()
//            );
//
//            log.info("Cleaned path: {}", cleaned);
//
//            return cleaned;
//        }
//
//        return normalized;
//    }
}