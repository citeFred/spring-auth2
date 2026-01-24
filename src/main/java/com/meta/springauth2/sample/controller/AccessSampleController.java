package com.meta.springauth2.sample.controller;

import com.meta.springauth2.sample.dto.SampleResponseDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/sample")
public class AccessSampleController {
    @GetMapping("permitAll")
    public ResponseEntity<SampleResponseDto> getSampleWithoutPermission() {
        SampleResponseDto sampleResponseDto = new SampleResponseDto("Login information is not required.");
        return ResponseEntity.ok(sampleResponseDto);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("adminOnly")
    public ResponseEntity<SampleResponseDto> getSampleWithAdminPermission() {
        SampleResponseDto sampleResponseDto = new SampleResponseDto("You're an admin.");
        return ResponseEntity.ok(sampleResponseDto);
    }
}