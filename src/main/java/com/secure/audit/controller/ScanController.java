package com.secure.audit.controller;

import com.secure.audit.model.ApiResponse;
import com.secure.audit.model.ScanResponse;
import com.secure.audit.model.Vulnerability;
import com.secure.audit.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanController {

    private final ScanOrchestratorService scanOrchestratorService;

    @PostMapping
    public ResponseEntity<ScanResponse> scanProject(
            @RequestParam("file") MultipartFile file
    ) {

        return ResponseEntity.ok(
                scanOrchestratorService.scanProject(file)
        );
    }
}