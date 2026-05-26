package com.secure.audit.dto.semgrep;



import lombok.Data;

import java.util.List;

@Data
public class SemgrepResponse {

    private List<SemgrepResult> results;
}