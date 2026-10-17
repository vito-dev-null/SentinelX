package com.enterprise.siem.agent;
import com.enterprise.siem.model.*; import com.enterprise.siem.util.JsonUtil; import java.time.Instant; import java.util.*;
public final class DemoEventGenerator { private DemoEventGenerator(){} public static void send(String host,int port) throws Exception {try(var client=new SIEMClient(host,port)){for(int i=0;i<5;i++){var e=new SecurityEvent(null,Instant.now(),"demo-node","demo-node","WARN","sshd","Failed password for admin from 10.0.0.50","10.0.0.50",null,"admin",EventType.AUTH_FAILURE,Map.of("demo","true"));client.send(JsonUtil.write(e));}}}
 public static void main(String[] args) throws Exception { send(args.length > 0 ? args[0] : "127.0.0.1", args.length > 1 ? Integer.parseInt(args[1]) : 5050); }
}
