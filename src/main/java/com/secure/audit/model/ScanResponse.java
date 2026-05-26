package com.secure.audit.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanResponse {

    private Integer critical;

    private Integer high;

    private Integer medium;

    private Integer low;

    private Integer totalFindings;

    private String reportPath;

    private List<Vulnerability> findings;
}
