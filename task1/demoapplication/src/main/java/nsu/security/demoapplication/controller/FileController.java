package nsu.security.demoapplication.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.tika.Tika;


@RestController
public class FileController {

    private static final String UPLOAD_DIR = "/app/uploads";
    private static final Logger log = LoggerFactory.getLogger(FileController.class);

    @Operation(summary = "Загрузить файл на сервер")
    @RequestBody(
            content = @Content(
                    mediaType = MediaType.MULTIPART_FORM_DATA_VALUE,
                    schema = @Schema(
                            type = "object",
                            requiredProperties = {"file"}
                    ),
                    schemaProperties = {
                            @io.swagger.v3.oas.annotations.media.SchemaProperty(
                                    name = "file",
                                    schema = @Schema(type = "string", format = "binary")
                            )
                    }
            )
    )
    @PostMapping(value = "/files", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) throws IOException {
        
        if (!isAllowedImageType(file)) {
            return ResponseEntity.badRequest().body("Разрешены только файлы PNG и JPEG");
        }   
        
        Path uploadPath = Paths.get(UPLOAD_DIR);
        Files.createDirectories(uploadPath);

        Path destination = uploadPath.resolve(file.getOriginalFilename());
        file.transferTo(destination);

        return ResponseEntity.ok("Файл сохранён: " + destination);
    }

    @GetMapping("/files")
    public ResponseEntity<Resource> getFile(@RequestParam String filename) throws IOException {
        Path filePath = Paths.get(UPLOAD_DIR).resolve(filename).normalize();
        Path uploadDir = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();
        
        log.info("uploadDir: {}", uploadDir);
        log.info("filePath: {}", filePath);

        if (!filePath.startsWith(uploadDir)) {
            return ResponseEntity.badRequest().build();
        }

        if (!Files.exists(filePath)) {
            return ResponseEntity.notFound().build();
        }

        String contentType = Files.probeContentType(filePath);
        if (contentType == null) {
            contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        }

        Resource resource = new FileSystemResource(filePath);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(resource);
    }

    @GetMapping("/files/resize")
    public ResponseEntity<Resource> resizeFile(@RequestParam String filename, @RequestParam String resizeParam) throws IOException {
        Path filePath = Paths.get(UPLOAD_DIR).resolve(filename).normalize();
        Path uploadDir = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();
        
        log.info("uploadDir: {}", uploadDir);
        log.info("filePath: {}", filePath);

        if (!filePath.startsWith(uploadDir)) {
            return ResponseEntity.badRequest().build();
        }

        if (!Files.exists(filePath)) {
            return ResponseEntity.notFound().build();
        }

        String contentType = Files.probeContentType(filePath);
        if (contentType == null) {
            contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        }

        String newPath = filePath.toString() + ".mut.png";
        String command = "convert " + filePath.toString() + " -resize " + resizeParam + " " + newPath;
        log.info("Command: {}", command);

        Process process = new ProcessBuilder("/bin/sh", "-c", command).start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                log.info("Process output: {}", line);
            }
            int exitCode = process.waitFor();
            log.info("Process finished with exit code: {}", exitCode);
        } catch (InterruptedException e) {
            log.error("Command: {}, interrupted {}", command, e.getMessage());
        }

        Resource resource = new FileSystemResource(newPath);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(resource);
    }

    @GetMapping("/files/resize_fix")
    public ResponseEntity<Resource> resizeFileFix(@RequestParam String filename, @RequestParam String resizeParam) throws IOException {
        Path filePath = Paths.get(UPLOAD_DIR).resolve(filename).normalize();
        Path uploadDir = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();
        
        log.info("uploadDir: {}", uploadDir);
        log.info("filePath: {}", filePath);

        if (!resizeParam.matches("\\d+x\\d+[!<>^@%]*")) {
            return ResponseEntity.badRequest().build();
        }

        if (!filePath.startsWith(uploadDir)) {
            return ResponseEntity.badRequest().build();
        }

        if (!Files.exists(filePath)) {
            return ResponseEntity.notFound().build();
        }

        String contentType = Files.probeContentType(filePath);
        if (contentType == null) {
            contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        }

        String newPath = filePath.toString() + ".mut.png";
        String command = "convert " + filePath.toString() + " -resize " + resizeParam + " " + newPath;
        log.info("Command: {}", command);

        ProcessBuilder pb = new ProcessBuilder(
            "convert",
            filePath.toString(),
            "-resize", resizeParam,
            newPath
        );

        log.info("Command: {}", pb.command());
        Process process = pb.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                log.info("Process output: {}", line);
            }
            int exitCode = process.waitFor();
            log.info("Process finished with exit code: {}", exitCode);
        } catch (InterruptedException e) {
            log.error("Command: {}, interrupted {}", command, e.getMessage());
        }

        Resource resource = new FileSystemResource(newPath);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(resource);
    }

    private static final Tika tika = new Tika();
    private static final List<String> ALLOWED_TYPES = List.of("image/png", "image/jpeg");

    private boolean isAllowedImageType(MultipartFile file) throws IOException {
        String detectedType = tika.detect(file.getInputStream());
        return ALLOWED_TYPES.contains(detectedType);
    }
}