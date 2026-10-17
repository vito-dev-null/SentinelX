package com.enterprise.siem.security;
import com.enterprise.siem.model.*;
public interface SecurityAuditLogger { boolean log(Incident incident, Alert alert, String action, String result); }
