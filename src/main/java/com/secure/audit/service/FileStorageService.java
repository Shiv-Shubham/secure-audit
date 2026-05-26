package com.secure.audit.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@Service
@Slf4j
public class FileStorageService {

    private static final String TEMP_DIR = "temp-scans";

    public Path saveZipFile(MultipartFile file) throws IOException {

        String scanId = UUID.randomUUID().toString();

        Path scanDir = Paths.get(TEMP_DIR, scanId);

        Files.createDirectories(scanDir);

        Path zipPath = scanDir.resolve(file.getOriginalFilename());

        Files.copy(
                file.getInputStream(),
                zipPath,
                StandardCopyOption.REPLACE_EXISTING
        );

        log.info("ZIP file stored at: {}", zipPath);

        return zipPath;
    }
}