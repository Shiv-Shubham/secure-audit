package com.secure.audit.model;


import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AiSuggestion {

    private String explanation;

    private String risk;

    private String recommendation;
}
