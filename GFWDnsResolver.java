

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Hashtable;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a tool used to prevent GFW DNS poisoning and return to the correct ip
 * @author chengkai
 * mail chengkai.me@gmail.com
 *
 */
public class GFWDnsResolver {
	
	private static GFWDnsResolver resolver = null;
	
	public  static  String DNS_SERVER = "8.8.8.8";
	
	private boolean debug = true;
	
	private int maxTryTimes = 2;
	private int waitTimes = 3;
	
	private Hashtable<String, String> dnsCache = new Hashtable<String, String>();
	
	//The gfw dns poisoning fake ip list , if we resolve domain return ip in blacklist
	//we will ignore udp package until receive correct ip 
	String[] blackList = {
			"74.125.127.102", "74.125.155.102", "74.125.39.102", "74.125.39.113",
			 "209.85.229.138",
			 "128.121.126.139", "159.106.121.75", "169.132.13.103", "192.67.198.6",
			 "202.106.1.2", "202.181.7.85", "203.161.230.171", "203.98.7.65",
			 "207.12.88.98", "208.56.31.43", "209.145.54.50", "209.220.30.174",
			 "209.36.73.33", "211.94.66.147", "213.169.251.35", "216.221.188.182", 
			 "216.234.179.13", "243.185.187.39", "37.61.54.158", "4.36.66.178",
			 "46.82.174.68", "59.24.3.173", "64.33.88.161", "64.33.99.47",
			 "64.66.163.251", "65.104.202.252", "65.160.219.113", "66.45.252.237",                                                                                                                           
			 "72.14.205.104", "72.14.205.99", "78.16.49.15", "8.7.198.45", "93.46.8.89",
	};
	
	
	
	final protected static char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	
	
	public static GFWDnsResolver instance() {
		if(resolver == null) {
			resolver = new GFWDnsResolver();
		}
		return resolver;
	}
	
	private GFWDnsResolver() {
		
	}
	
	private boolean isBadReply(String ip) {
		for(int i = 0 ; i < blackList.length; i++ ) {
			if(blackList[i].equals(ip)) {
				return true;
			}
		}
		return false;
	}
	public String gfwResolve(String domain) throws IOException {
		
		InetAddress address = InetAddress.getByName(domain);
		String ip = address.getHostAddress();
		if(!isBadReply(ip)) {
			return ip;
		} else if(dnsCache.containsKey(domain)) {
			return dnsCache.get(domain) ;
		}
		
		for(int i= 0; i < maxTryTimes; i ++ ) {
			 ip = resolve(domain);
//			if(ip == null) {
//				throw new IllegalStateException("can't obtain ip address from dns answer package");
//			}
			if(isBadReply(ip) || ip == null) {
				continue;
			} else {
				//is croret ip address for domain.
				dnsCache.put(domain, ip);
				return ip;
			}
		}
		
		throw new IllegalStateException("try to resolve domain over max times");
	}
	
	
	
	
	private String resolve(String domain) throws IOException {
		byte[] recvData = new byte[512];
		byte[] data = buildRequestData(domain);
		String result = null;
		if(debug) {
			System.out.println(" =============== dns query request package dump: ================");
			hexDump(data);
		}
		
		//Prepare send dns query request packate
		DatagramSocket  dataSocket = new DatagramSocket();
		
		InetAddress inet = InetAddress.getByName(DNS_SERVER);
		DatagramPacket dataPacket = new DatagramPacket(data,data.length, inet,53);
		dataSocket.send(dataPacket);
		
		//prepare receive the dns answer package
		byte[] respData = null;
		for(int i = 0 ; i < waitTimes; i++) {
			DatagramPacket receivePacket = new DatagramPacket(recvData, recvData.length) ;
			dataSocket.receive(receivePacket);
			respData = receivePacket.getData();
			if(respData != null) {
				if(debug) {
					System.out.println("============ dns query answer package dump");
					hexDump(respData);
				}
				
				String ip =  decodeDnsResponse(respData,domain);
				if(isBadReply(ip)) {
					continue;
				} else {
					result = ip;
					break;
				}
				
			} else {
				throw new  IOException("dns resolve no response");
			}
			
		}
		
		return result;
		
	}
	
	private void hexDump(byte[] bytes) {
		System.out.println(bytesToHex(bytes));
	}
	
	private  String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	

	private byte[] buildRequestData(String host) {
		//head + (host length +1) + eof sign + qtype + qclass
		int size = 12 + host.length() + 1 + 1+ 4;
		ByteBuffer buff = ByteBuffer.allocate(size);
		
		Random random = new Random();
		byte[] seq = new byte[2];
		random.nextBytes(seq);
		buff.put(seq);
		byte[] header = {0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
		buff.put(header);
		//add query question domain field
		String[] parts = host.split("\\.");
		for(int i= 0; i < parts.length;i++) {
			buff.put((byte) parts[i].length());
			buff.put(parts[i].getBytes());
		}
		buff.put((byte)0x00);
		byte[] tmp = {0x00,0x01,0x00,0x01};
		buff.put(tmp);
		
		return buff.array();
	}
	
	 //extract ip address from dns answer package
	 private String  decodeDnsResponse(byte[] resp,String host) {
		
		ByteBuffer buffer = ByteBuffer.wrap(resp);
		//parse the query answer count.
		int pos = 6;
		buffer.position(pos);
		short qncount = buffer.getShort();
//		for(int i = 0; i)
		//skip query answer field
		pos = 12 + 1+ host.length() + 1 + 4;
		buffer.position(pos);
		for(int i= 0 ; i < qncount; i++ ) {
			buffer.position(pos);
			byte pointFlg = buffer.get();
			if((pointFlg & 0xc0) == 0xc0 ) {
				pos+=2;  //point 
			} else {
				pos+= 1+ host.length() + 1;
			}
			
			buffer.position(pos);
			int queryType =  buffer.getShort();
			
			if(debug) {
				System.out.println("qncount:" + qncount + "pos:" + pos + "queryType:" + queryType);
			}
			
			pos += 8;
			buffer.position(pos);
			int dataLen = buffer.getShort();
			pos +=2; //move to data area
			//A record
			if(queryType == 0x0001) {
				if(debug) System.out.println("parse A record");
				
				String ip = "";
				for(int j = 0; j < dataLen ; j ++) {
					buffer.position(pos);
					int v  = buffer.get();
					v = v>0?v:0x0ff & v;
					ip += v + (j== dataLen -1 ? "":".");
					pos+=1;
				}
				// System.out.println("ip:" + ip);
				//return first available ip
				return ip;
				
			} else {
				pos+=dataLen;
			}
		}
		
		return null;
	}

	public static void main(String[] args) throws IOException {
		if(args.length == 0) 
		{
			System.out.println("Usage: GFWDnsResolver <domain>");
		} else {
			String host = args[0];
			String ip = GFWDnsResolver.instance().gfwResolve(host);
			System.out.println("host:" + host + " The real ip is:"  + ip);
			
		}
	}
}
