/**
 * This program reads a set of packets and produces a detailed summary of those packets.
 * 
 * @author Shristika Yadav
 */
		
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Scanner;

public class PktAnalyzer {
	static byte b = 0;
	
		
	/**
	 * This method is used to extract and print the ethernet header.
	 * This method has been called from the main method.
	 * 
	 * @param fileData is an array which consist of all the data from the file mentioned by the user. 
	 * @param fileLength is the size of file.
	 */
	static void etherHeader(byte[] fileData,long fileLength)
	{
		
		int etherBytesToExtract[] = {6,6,2};
		ArrayList<String> etherHeaderData = new ArrayList<>();
		etherHeaderData.add(String.valueOf(fileLength));	

		int count = 0;
		
		for(int i=0;i<etherBytesToExtract.length;i++){
			String str = "";
			StringBuffer strBuffer = new StringBuffer("");
			for(int j=0;j<etherBytesToExtract[i];b++,j++)
			{
				str = Integer.toHexString((fileData[b]& 0xff)+256).substring(1);
				strBuffer.append(str);
			}
			// to divide the data.
			if(i == 0 || i ==1){
				for(int l1=0;l1<strBuffer.length();l1++){
					if((l1+1) % 3==0){
						strBuffer.insert(l1, ":");
					}
				}
			}
				etherHeaderData.add(strBuffer.toString());
			
			}
	
		System.out.println("ETHER:   ------ Ether Header ------");
		System.out.println("ETHER:   ");
		System.out.println("ETHER:   Packet Size = "+ etherHeaderData.get(count++) + " bytes");
		System.out.println("ETHER:   Destination = "+etherHeaderData.get(count++));
		System.out.println("ETHER:   Source = " + etherHeaderData.get(count++));
		System.out.println("ETHER:   EtherType = "+ etherHeaderData.get(count)+"  (IP)");
		System.out.println("ETHER:   ");
		
		ipHeader(fileData);
		
		
	}
	

	/**
	 * This method is used to extract and display the ip header.
	 * It has been called from the etherHeader method. 
	 * 
	 * @param fileData is an array which consist of all the data from the file mentioned by the user.
	 */
	static void ipHeader(byte[] fileData)
	{
		int ipBytesToExtract[] = {1,1,2,2,2,1,1,2,4,4};
		ArrayList<String> ipHeaderData = new ArrayList<>();
		
		int count = 0;
		
		for(int i=0;i<ipBytesToExtract.length;i++){
			String str = "";
			StringBuffer strBuffer = new StringBuffer("");
			for(int j=0;j<ipBytesToExtract[i];b++,j++)
			{
				str = Integer.toHexString((fileData[b]& 0xff)+256).substring(1);
				strBuffer.append(str);
				
			}
			if(i == 0)
			{
				ipHeaderData.add(String.valueOf(strBuffer.charAt(0)));
				ipHeaderData.add(String.valueOf(Integer.parseInt(String.valueOf(strBuffer.charAt(1)))*4));
			}else if (i == 2 || i == 6 || i == 5)
			{
				//convert to decimal
				String a = String.valueOf(Long.parseLong(strBuffer.toString(), 16 ));
				ipHeaderData.add(a);
			}else if (i == 4){
				Long one = Long.parseLong(strBuffer.toString(),16);
				String binary=String.format("%16s",Long.toBinaryString(one)).replace(' ', '0');
				strBuffer = new StringBuffer("");
				for(int num=0;num<binary.length();num++){
					if(num<3){
						strBuffer.append(binary.charAt(num));
					}else if(num ==3){
						int a = Integer.parseInt(strBuffer.toString(), 2); 
						ipHeaderData.add("0x"+String.valueOf(a));
						strBuffer = new StringBuffer("");
						strBuffer.append(binary.charAt(num));
					}else{
						strBuffer.append(binary.charAt(num));
					}
				}
				int a = Integer.parseInt(strBuffer.toString(),2);
				ipHeaderData.add(String.valueOf(a));
				
			}
			else if (i == 8 || i == 9)
			{
				//convert to binary
				Long one = Long.parseLong(strBuffer.toString(),16);
				strBuffer = new StringBuffer("");
				String binary=Long.toBinaryString(one);
				//convert to decimal
				StringBuffer str1 = new StringBuffer("");
				for(int low=0;low<32;low++){
					str1.append(binary.charAt(low));
					if((low+1) % 8 == 0){
						String a = String.valueOf(Integer.parseInt(str1.toString(), 2 ));
						str1 = new StringBuffer("");
						strBuffer.append(a+".");
					}
				}
				
				strBuffer.deleteCharAt(strBuffer.length()-1);
				ipHeaderData.add(strBuffer.toString());
				try {
					InetAddress ip = InetAddress.getByName(strBuffer.toString());
					if(ip.getHostName().equals(ip.getHostAddress()))
					{
						ipHeaderData.add("(Unknown hostname)");
					}else
						ipHeaderData.add(ip.getHostName());
				} catch (UnknownHostException e) 
				{
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}else if (i == 7)
			{	
				
				if(ipHeaderData.get(8).equals("6"))
				{
					ipHeaderData.add(" (TCP)");
				}
				else if(ipHeaderData.get(8).equals("17"))
				{
					ipHeaderData.add(" (UDP)");
				}
				else if(ipHeaderData.get(8).equals("1"))
				{
					ipHeaderData.add(" (ICMP)");
				}
				
				ipHeaderData.add(strBuffer.toString());
			}
			else
			{
				ipHeaderData.add(strBuffer.toString());
			}
		}
		
		
		System.out.println("IP:   ------ IP Header ------");
		System.out.println("IP:   ");
		System.out.println("IP:   Version = "+ ipHeaderData.get(count++));
		System.out.println("IP:   Header length = "+ ipHeaderData.get(count++) + " bytes");
		System.out.println("IP:   Type of Service = "+ ipHeaderData.get(count));
		
		
		Long one = Long.parseLong(ipHeaderData.get(count),16);
		String binary=String.format("%16s",Long.toBinaryString(one)).replace(' ', '0');
		StringBuffer std = new StringBuffer();
		for(int num = 0;num<binary.length()-2;num++){
			if(num<3){
				std.append(binary.charAt(num));
			}
			if(num==3){
				System.out.println("IP:       "+std.toString()+". .... = Precedence");
				System.out.print("IP:       ..."+binary.charAt(num)+" .... = ");
				if(binary.charAt(num)=='0')
					System.out.println("Normal Delay");
				else
					System.out.println("    = Low Delay");
			}
			else if(num == 4){
				System.out.print("IP:       .... "+binary.charAt(num)+"... = ");
				if(binary.charAt(num)=='0')
					System.out.println("Normal ThroughPut");
				else
					System.out.println("    = High Throughput");
			}
			else if(num == 5){
				System.out.print("IP:       .... ."+binary.charAt(num)+".. = ");
				if(binary.charAt(num)=='0')
					System.out.println("Normal Reliability");
				else
					System.out.println("    = High Reliability");
			}
			
		}
		++count;
		System.out.println("IP:   Total Length = "+ ipHeaderData.get(count++)+" bytes");
		System.out.println("IP:   Identification = "+ ipHeaderData.get(count++));
		System.out.println("IP:   Flags = "+ipHeaderData.get(count));
		String data = ipHeaderData.get(count);
		for(int num =0;num<data.length();num++){
			if(data.charAt(num)=='1')
				System.out.println("              ."+data.charAt(num)+".. ...."+" = do not fragment ");
			else
				System.out.println("              .."+data.charAt(num)+". ...."+" = last fragment ");
		}
		count++;
		System.out.println("IP:   Fragment offset = "+ ipHeaderData.get(count++) + " bytes");
		System.out.println("IP:   Time to live = "+ ipHeaderData.get(count++) +" seconds/hops");
		System.out.println("IP:   Protocol = "+ ipHeaderData.get(count++)+" "+ipHeaderData.get(count++));
		System.out.println("IP:   Header checksum = "+ ipHeaderData.get(count++));
		System.out.println("IP:   Source address = "+ ipHeaderData.get(count++)+"    "+ipHeaderData.get(count++));
		System.out.println("IP:   Destination address = "+ ipHeaderData.get(count++)+"    "+ipHeaderData.get(count));
		System.out.println("IP:   ");
		
		if(ipHeaderData.get(8).equals("6"))
		{
			tcpHeader(fileData);
		}
		if(ipHeaderData.get(8).equals("17"))
		{
			udpHeader(fileData);
		}
		if(ipHeaderData.get(8).equals("1"))
		{
			icmpHeader(fileData);
		}
	}

	
	
	/**
	 * 
	 * This method is used to extract and display the tcp header.
	 * It has been called from the ipHeader method. 
	 * 
	 * @param fileData is an array which consist of all the data from the file mentioned by the user.
	 */
	static void tcpHeader(byte[] fileData)
	{
		int tcpBytesToExtract[] = {2,2,4,4,2,2,2,2,8,8,8,8};
		ArrayList<String> tcpHeaderData = new ArrayList<>();
		int count = 0;
		for(int i=0;i<tcpBytesToExtract.length;i++){
			String str = "";
			StringBuffer strBuffer = new StringBuffer("");
			for(int j=0;j<tcpBytesToExtract[i];b++,j++)
			{
				str = Integer.toHexString((fileData[b]& 0xff)+256).substring(1);
				strBuffer.append(str);
			}
			if(i==6)
			{
				tcpHeaderData.add(strBuffer.toString());
			}
			else if(i == 4){
				String data = strBuffer.toString();
				Long hex = Long.parseLong(data.toString().trim(),16);
				String binary=Long.toBinaryString(hex);
				strBuffer = new StringBuffer();
				for(int num=0;num<binary.length();num++){
					if(num < 4 || (num>4 && num<7) || (num>7)){
						strBuffer.append(binary.charAt(num));
					}else if (num == 4){
						tcpHeaderData.add(String.valueOf(Integer.parseInt(strBuffer.toString(),2)));
						strBuffer = new StringBuffer();
						strBuffer.append(binary.charAt(num));
					}else if (num == 7){
						tcpHeaderData.add(strBuffer.toString());
						strBuffer = new StringBuffer();
						strBuffer.append(binary.charAt(num));
					}
				}
				tcpHeaderData.add(strBuffer.toString());
			}

			else if (i>7){
				tcpHeaderData.add(strBuffer.toString());
			}
			else
			{
				//converted into decimal
				String a = String.valueOf(Long.parseLong(strBuffer.toString(), 16 ));
				tcpHeaderData.add(a);
			}
		}
		System.out.println("TCP:   ------TCP Header------");
		System.out.println("TCP:   ");
		System.out.println("TCP:   Source port = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   Destination = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   Sequence Number = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   Acknowledgement = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   Data Offset = "+tcpHeaderData.get(count++)+" bytes");
		System.out.println("TCP:   Reserved = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   Flags = "+tcpHeaderData.get(count));
		String data = tcpHeaderData.get(count);
		if(data.charAt(3)=='0')
			System.out.println("TCP:         .."+data.charAt(3)+". .... = No Urgent Pointer");
		else
			System.out.println("TCP:         .."+data.charAt(3)+". .... = Urgent pointer");
		
		if(data.charAt(4)=='0')
			System.out.println("TCP:         ..."+data.charAt(4)+" .... = No Acknowledgement");
		else
			System.out.println("TCP:         ..."+data.charAt(4)+" .... = Acknowledgement");
		
		if(data.charAt(5)=='0')
			System.out.println("TCP:         .... "+data.charAt(5)+"... = No Push function");
		else
			System.out.println("TCP:         .... "+data.charAt(5)+"... = Push function");
		if(data.charAt(6)=='0')
			System.out.println("TCP:         .... ."+data.charAt(6)+".. = No Reset");
		else
			System.out.println("TCP:         .... ."+data.charAt(6)+".. = Reset");
		
		if(data.charAt(7)=='0')
			System.out.println("TCP:         .... .."+data.charAt(7)+". = No Sync");
		else
			System.out.println("TCP:         .... .."+data.charAt(7)+". = Sync");
		if(data.charAt(8)=='0')
			System.out.println("TCP:         .... ..."+data.charAt(8)+" = No Fin");
		else
			System.out.println("TCP:         .... ..."+data.charAt(8)+" = Fin");
		count++;
		System.out.println("TCP:   Window = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   Checksum = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   Urgent pointer = "+tcpHeaderData.get(count++));
		System.out.println("TCP:   ");
		for(int num = 0;num<4;num++){
			System.out.print("TCP:   Data : ");
			String dataToPrint = tcpHeaderData.get(count++);
			for(int gap = 0;gap<dataToPrint.length();gap++){
				System.out.print(dataToPrint.charAt(gap));
				if((gap+1) % 4 == 0)
					System.out.print(" ");
			}
			System.out.println();

		}
		
	}
	
	
	/**
	 * 
	 * This method is used to extract and display the udp header.
	 * It has been called from the ipHeader method. 
	 * @param fileData is an array which consist of all the data from the file mentioned by the user.
	 */
	static void udpHeader(byte[] fileData)
	{
		int udpBytesToExtract[] = {2,2,2,2,8,8,8,8};
		int count = 0;
		ArrayList<String> udpHeaderData = new ArrayList<>();
		for(int i=0;i<udpBytesToExtract.length;i++)
		{
			String str = "";
			StringBuffer strBuffer = new StringBuffer("");
			for(int j=0;j<udpBytesToExtract[i];j++,b++)
			{
				str = Integer.toHexString((fileData[b]& 0xff)+256).substring(1);
				strBuffer.append(str);
			}
			if(i>2)
			{
				// converted into hex
				udpHeaderData.add(strBuffer.toString());
			}else
			{
				//converted into decimal
				String a = String.valueOf(Long.parseLong(strBuffer.toString(), 16 ));
				udpHeaderData.add(a);
			}
		}
		System.out.println("UDP:   ------ UDP Header ------");
		System.out.println("UDP:   ");
		System.out.println("UDP:   Source port = "+udpHeaderData.get(count++));
		System.out.println("UDP:   Destination port = "+udpHeaderData.get(count++));
		System.out.println("UDP:   Length = "+udpHeaderData.get(count++));
		System.out.println("UDP:   Checksum = "+udpHeaderData.get(count++));
		System.out.println("UDP:   ");

		for(int num = 0;num<4;num++){
			System.out.print("UDP:   Data : ");
			String dataToPrint = udpHeaderData.get(count++);
			for(int gap = 0;gap<dataToPrint.length();gap++){
				System.out.print(dataToPrint.charAt(gap));
				if((gap+1) % 4 == 0)
					System.out.print(" ");
			}
			System.out.println();

		}

	}
	
	
	/**
	 * 
	 * This method is used to extract and display the icmp header.
	 * It has been called from the ipHeader method. 
	 * 
	 * @param fileData is an array which consist of all the data from the file mentioned by the user.
	 */
	static void icmpHeader(byte[] fileData)
	{
		int icmpBytesToExtract[] = {1,1,2};
		ArrayList<String> icmpHeaderData = new ArrayList<>();
		int count = 0;
		for(int i=0;i<icmpBytesToExtract.length;i++){
			String str = "";
			StringBuffer strBuffer = new StringBuffer("");
			for(int j=0;j<icmpBytesToExtract[i];j++,b++)
			{
				str = Integer.toHexString((fileData[b]& 0xff)+256).substring(1);
				strBuffer.append(str);
			}
			if(i == 2)
			{
				icmpHeaderData.add(strBuffer.toString());
			}else 
			{
				String a = String.valueOf(Long.parseLong(strBuffer.toString(), 16 ));
				icmpHeaderData.add(a);
			}
		}
		System.out.println("ICMP:   ------ ICMP Header ------");
		System.out.println("ICMP:   ");
		System.out.println("ICMP:   Type = "+icmpHeaderData.get(count++));
		System.out.println("ICMP:   Code = "+icmpHeaderData.get(count++));
		System.out.println("ICMP:   Checksum = "+icmpHeaderData.get(count++));
	}
	
	/**
	 * main method takes input of the file name from user, reads it into an array and then calls 
	 * etherHeader method to extract and display the ether header. 
	 * 
	 */
	public static void main(String args[])
	{
		System.out.println("Enter the name of the file?");
		Scanner sc = new Scanner(System.in);
		String fileName = sc.nextLine();
		File file = new File(fileName+".bin");
		byte[] fileData = new byte[(int)file.length()];
		DataInputStream dis;
		
		try 
		{
			dis = new DataInputStream(new FileInputStream(file));
			dis.readFully(fileData);
		} catch (FileNotFoundException e1) 
		{
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		//Ethernet
		etherHeader(fileData,file.length());
		
	}

}
