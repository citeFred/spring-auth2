package com.meta.springauth2.sample.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SampleResponseDto {
    private String message;

    public SampleResponseDto(String message) {
        this.message = message;
    }

}