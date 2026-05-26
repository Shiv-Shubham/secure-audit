package com.secure.audit.dto.semgrep;



import lombok.Data;

@Data
public class SemgrepResult {

    private String check_id;

    private String path;

    private Start start;

    private Extra extra;
}