package com.secure.audit.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.audit.dto.gitleaks.GitleaksFinding;
import com.secure.audit.model.Vulnerability;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class GitleaksScannerService {

    private final ObjectMapper objectMapper;
   public List<Vulnerability> runGitleaksScan(Path projectPath) {

       try {

           Path reportPath =
                   projectPath.resolve("gitleaks-report.json");

           ProcessBuilder processBuilder =
                   new ProcessBuilder(
                           "gitleaks",
                           "detect",
                           "--source",
                           projectPath.toString(),
                           "--report-format",
                           "json",
                           "--report-path",
                           reportPath.toString(),
                           "--no-git"
                   );

           processBuilder.redirectErrorStream(true);

           Process process = processBuilder.start();

           int exitCode = process.waitFor();

           log.info("Gitleaks finished with exit code: {}", exitCode);

           // Gitleaks returns exit code 1 when leaks are found
           // so don't fail because of non-zero exit code

           if (!Files.exists(reportPath)) {

               log.warn("Gitleaks report file not found");

               return new ArrayList<>();
           }

           String json =
                   Files.readString(reportPath);

           if (json.isBlank()) {
               return new ArrayList<>();
           }
          // log.info("Gitleaks JSON: {}", json);
           List<GitleaksFinding> findings =
                   objectMapper.readValue(
                           json,
                           new TypeReference<List<GitleaksFinding>>() {}
                   );

           return mapToVulnerabilities(findings);

       } catch (Exception e) {

           log.error("Error running Gitleaks", e);

           throw new RuntimeException(
                   "Gitleaks scan failed"
           );
       }
   }
    private List<Vulnerability> mapToVulnerabilities(
            List<GitleaksFinding> findings
    ) {

        List<Vulnerability> vulnerabilities =
                new ArrayList<>();

        for (GitleaksFinding finding : findings) {

            vulnerabilities.add(

                    Vulnerability.builder()
                            .type(finding.getRuleId())
                            .severity("HIGH")
                            .file(finding.getFile())
                            .line(finding.getStartLine())
                            .message(finding.getDescription())
                            .scanner("Gitleaks")
                            .build()
            );
        }

        return vulnerabilities;
    }

}
