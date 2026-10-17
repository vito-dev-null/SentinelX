package com.enterprise.siem;
import com.enterprise.siem.agent.EventClassifier; import com.enterprise.siem.model.EventType; import org.junit.jupiter.api.Test; import static org.junit.jupiter.api.Assertions.*;
class ClassifierTest {@Test void classifiesSshLines(){assertEquals(EventType.AUTH_FAILURE,EventClassifier.classify("Failed password for root from 10.0.0.1"));assertEquals(EventType.AUTH_SUCCESS,EventClassifier.classify("Accepted publickey for admin"));assertEquals(EventType.NETWORK_EVENT,EventClassifier.classify("firewall connection accepted"));}}
