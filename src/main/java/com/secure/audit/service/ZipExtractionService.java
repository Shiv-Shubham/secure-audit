package com.secure.audit.service;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Service
@Slf4j
public class ZipExtractionService {

    public Path extractZip(Path zipFilePath) throws IOException {

        Path extractionDir = zipFilePath.getParent().resolve("extracted");

        Files.createDirectories(extractionDir);

        try (ZipInputStream zis =
                     new ZipInputStream(Files.newInputStream(zipFilePath))) {

            ZipEntry zipEntry;

            while ((zipEntry = zis.getNextEntry()) != null) {

                Path newPath = resolveZipEntry(extractionDir, zipEntry);

                if (zipEntry.isDirectory()) {

                    Files.createDirectories(newPath);

                } else {

                    Files.createDirectories(newPath.getParent());

                    Files.copy(
                            zis,
                            newPath,
                            StandardCopyOption.REPLACE_EXISTING
                    );
                }

                zis.closeEntry();
            }
        }

        log.info("ZIP extracted successfully at: {}", extractionDir);

        return extractionDir;
    }

    private Path resolveZipEntry(Path targetDir, ZipEntry zipEntry)
            throws IOException {

        Path resolvedPath = targetDir.resolve(zipEntry.getName()).normalize();

        if (!resolvedPath.startsWith(targetDir)) {
            throw new IOException(
                    "Invalid ZIP entry: " + zipEntry.getName()
            );
        }

        return resolvedPath;
    }
}