package com.secure.audit.service;



import com.secure.audit.model.ScanResponse;
import com.secure.audit.model.Vulnerability;
//import com.secure.audit.scanner.GitleaksScannerService;
//import com.secure.audit.scanner.SemgrepScannerService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ScanOrchestratorService {

    private final FileStorageService fileStorageService;

    private final ZipExtractionService zipExtractionService;

    private final SemgrepScannerService semgrepScannerService;

    private final GitleaksScannerService gitleaksScannerService;

    private final HtmlReportService htmlReportService;


    public ScanResponse scanProject(MultipartFile file) {

        try {

            Path zipPath =
                    fileStorageService.saveZipFile(file);

            Path extractedPath =
                    zipExtractionService.extractZip(zipPath);

            List<Vulnerability> vulnerabilities =
                    new ArrayList<>();

            vulnerabilities.addAll(
                    semgrepScannerService
                            .runSemgrepScan(extractedPath)
            );

            vulnerabilities.addAll(
                    gitleaksScannerService
                            .runGitleaksScan(extractedPath)
            );

            ScanResponse response= buildScanResponse(vulnerabilities);
            String reportPath =
                    htmlReportService.generateReport(
                            response
                    );
            response.setReportPath(reportPath);

           return response;

        } catch (Exception e) {

            throw new RuntimeException(
                    "Scan failed: " + e.getMessage()
            );
        }
    }

    private ScanResponse buildScanResponse(
            List<Vulnerability> vulnerabilities
    ) {

        long critical =
                vulnerabilities.stream()
                        .filter(v ->
                                "CRITICAL".equalsIgnoreCase(
                                        v.getSeverity()
                                )
                        )
                        .count();

        long high =
                vulnerabilities.stream()
                        .filter(v ->
                                "HIGH".equalsIgnoreCase(
                                        v.getSeverity()
                                )
                        )
                        .count();

        long medium =
                vulnerabilities.stream()
                        .filter(v ->
                                "MEDIUM".equalsIgnoreCase(
                                        v.getSeverity()
                                )
                        )
                        .count();

        long low =
                vulnerabilities.stream()
                        .filter(v ->
                                "LOW".equalsIgnoreCase(
                                        v.getSeverity()
                                )
                        )
                        .count();

        return ScanResponse.builder()
                .critical((int) critical)
                .high((int) high)
                .medium((int) medium)
                .low((int) low)
                .totalFindings(vulnerabilities.size())
                .findings(vulnerabilities)
                .build();
    }
}
