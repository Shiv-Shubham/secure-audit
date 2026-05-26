package com.secure.audit.dto.gitleaks;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class GitleaksFinding {
    @JsonProperty("RuleID")
    private String ruleId;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("File")
    private String file;

    @JsonProperty("StartLine")
    private Integer startLine;
}