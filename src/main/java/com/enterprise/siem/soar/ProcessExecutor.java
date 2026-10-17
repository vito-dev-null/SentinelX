package com.enterprise.siem.soar;
import java.util.List;
public final class ProcessExecutor { public int execute(ResponseAction action, boolean dryRun) throws Exception { if (dryRun) return 0; throw new UnsupportedOperationException("real SOAR execution is not enabled"); } public List<ResponseAction> allowedActions(){ return List.of(ResponseAction.values()); } }
