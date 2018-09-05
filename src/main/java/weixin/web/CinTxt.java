package weixin.web;

import java.io.*;

public class CinTxt {  
	public static void main(String args[]) {  
		try { // 防止文件建立或读取失败，用catch捕捉错误并打印，也可以throw  
			
			/* 写入Txt文件 */  
			File writename = new File("F:\\input.txt"); // 相对路径，如果没有则要建立一个新的output。txt文件  
			writename.createNewFile(); // 创建新文件  
			BufferedWriter out = new BufferedWriter(new FileWriter(writename));  
			out.write("我会写入文件啦\r\n"); // \r\n即为换行  
			out.flush(); // 把缓存区内容压入文件  
			out.close(); // 最后记得关闭文件  

			/* 读入TXT文件 */  
			File filename = new File("F:\\input.txt"); // 要读取以上路径的input。txt文件  
			// 建立一个输入流对象reader
			InputStreamReader reader = new InputStreamReader(new FileInputStream(filename));   
			BufferedReader br = new BufferedReader(reader); // 建立一个对象，它把文件内容转成计算机能读懂的语言  
			String line = "";  
			line = br.readLine();  
 
			System.out.println(line);
			
		} catch (Exception e) {  
			e.printStackTrace();  
		}  
	}  
}  