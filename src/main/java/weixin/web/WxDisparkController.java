package weixin.web;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.jeewx.api.core.exception.WexinReqException;
import org.jeewx.api.mp.aes.AesException;
import org.jeewx.api.mp.aes.WXBizMsgCrypt;
import org.jeewx.api.third.JwThirdAPI;
import org.jeewx.api.third.model.ApiComponentToken;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@Controller
public class WxDisparkController {
	
	private static final String FILE = "F:\\input.txt";
	
	/**
	 * 微信全网测试账号
	 */
	private static final  String COMPONENT_APPID = "xxxxxxxxxx";
	private static final  String COMPONENT_APPSECRET = "xxxxxxxxxx";
	private static final  String COMPONENT_ENCODINGAESKEY = "xxxxxxxxxx";
	private static final  String COMPONENT_TOKEN = "xxxxxxxxxx";
	
	private Logger logger = Logger.getLogger(WxDisparkController.class);

	/**
     * 授权事件接收
     * @param request
     * @param response
     * @throws IOException
     * @throws AesException
     * @throws DocumentException
     */
    @RequestMapping(value = "/open/authorize",method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void acceptAuthorizeEvent(HttpServletRequest request, HttpServletResponse response) 
    		throws IOException, AesException {
        processAuthorizeEvent(request);
        output(response, "success"); // 输出响应的内容。
    }
    
    @RequestMapping(value = "/open/{appid}/callback")  
    public void acceptMessageAndEvent(HttpServletRequest request, HttpServletResponse response) throws IOException, AesException, DocumentException {  
        String msgSignature = request.getParameter("msg_signature");  
        if (!StringUtils.isNotBlank(msgSignature))  
            return;// 微信推送给第三方开放平台的消息一定是加过密的，无消息加密无法解密消息  
        StringBuilder sb = new StringBuilder();  
        BufferedReader in = request.getReader();  
        String line;  
        while ((line = in.readLine()) != null) {  
            sb.append(line);  
        }  
        in.close();  
        
        String xml = sb.toString();  
        logger.info("校验中..获取到xml" + xml);
        checkWeixinAllNetworkCheck(request,response,xml);  
    }  
	
    
    /**
     * 处理授权事件的推送
     * 
     * @param request
     * @throws IOException
     * @throws AesException
     * @throws DocumentException
     */
    public void processAuthorizeEvent(HttpServletRequest request) throws IOException, AesException {
        String nonce = request.getParameter("nonce");
        String timestamp = request.getParameter("timestamp");
        String signature = request.getParameter("signature");
        String msgSignature = request.getParameter("msg_signature");
 
        logger.info("自动检查，获取ticket.." + signature + " | " + msgSignature+ " | " + timestamp+ " | " + nonce);
        if (!StringUtils.isNotBlank(msgSignature))
            return;// 微信推送给第三方开放平台的消息一定是加过密的，无消息加密无法解密消息
        boolean isValid = checkSignature(COMPONENT_TOKEN, signature, timestamp, nonce);
        if (isValid) {
            StringBuilder sb = new StringBuilder();
            BufferedReader in = request.getReader();
            String line;
            while ((line = in.readLine()) != null) {
                sb.append(line);
            }
            String xml = sb.toString();
            logger.info("自动检查，获取ticket..  未解析xml之前:" + xml);
            String encodingAesKey = COMPONENT_ENCODINGAESKEY;// 第三方平台组件加密密钥
            WXBizMsgCrypt pc = new WXBizMsgCrypt(COMPONENT_TOKEN, encodingAesKey, COMPONENT_APPID);
            xml = pc.decryptMsg(msgSignature, timestamp, nonce, xml);
            logger.info("自动检查，获取ticket..  成功解析xml:" + xml);
            processAuthorizationEvent(xml);
        }
    }
    
    public static void main(String[] args) {
    	
    	/*try {
			String msgSignature = "xxxxxxxxxx";
			String timestamp = "xxxxxx";
			String nonce = "xxxxxxx";
			String xml = "<xml>    <ToUserName><![CDATA[gh_3c884a361561]]></ToUserName>    <Encrypt><![CDATA[ncCN6NmhUNQMVlsYxx8B5AOOxs9RKja4BKIh2/bK+TKr5H2OFjp5gEGih3hAzS35HLhCzuQ24NuDZvVJzUny/4ZECWxuD/5SXj7lxI1sYoy0vJmt3RMGWIsSf1YNUgnBFnsf05rj6badDatC2G6XmmHlwMZPHvMRia0ZuzEDZVOjyuw9+Y4ylys7tQ6IAJ6rgnbzKx/Foc8MrB8+inEUGLMk7qaBEr4gtmrlBtORFuL7nUrYSPINQ43/6hNxoG3CK99PjYsX69jCMKsSVraiHB7X9d7+GOq5YthJzByyQyjqG3yAMPzwEO7fnyGyfF3yfRynrx/bYG8iyCIG7q3QDHK5DDuAaOUF9Salr6cqnwF/nLtRT94KOgeNRov0XDCA312dDW5kd4FAoGA+7qu8nVnnsLYRsabmMy9bPxdPXeY3R65HFC7Y886P0vZnmXHo1FpKt32QLb12lxF1sCKykxXnWtv4MO4WgxMn2KCn+yncH1c8mwpa4KQFFfhLBQVxhuTy1tL/3U5z3ZMAQ4a1J/+DF3arCeyoibKi0x6i7Gugwl3YF9ImTEMm7tFUOrfUpZCjvGhLCLCSdd+RHLYc2Q==]]></Encrypt></xml>";
			
			WXBizMsgCrypt pc = new WXBizMsgCrypt(COMPONENT_TOKEN, COMPONENT_ENCODINGAESKEY, COMPONENT_APPID);
			String xs = pc.decryptMsg(msgSignature, timestamp, nonce, xml);
			
			System.out.println(xs);
		} catch (AesException e) {
			e.printStackTrace();
		}*/
  
    	
    	try {
			ApiComponentToken apiComponentToken = new ApiComponentToken();
			apiComponentToken.setComponent_appid(COMPONENT_APPID);
			apiComponentToken.setComponent_appsecret(COMPONENT_APPSECRET);
			String ticket = readFile();
			apiComponentToken.setComponent_verify_ticket(ticket);
			String component_access_token = JwThirdAPI.getAccessToken(apiComponentToken);
			
			System.out.println(component_access_token);
			
		} catch (WexinReqException e) {
			e.printStackTrace();
		}
    	
	}
    
    /**
     * 保存Ticket
     * @param xml
     */
    void processAuthorizationEvent(String xml){
    	Document doc;
		try {
			doc = DocumentHelper.parseText(xml);
			Element rootElt = doc.getRootElement();
			String ticket = rootElt.elementText("ComponentVerifyTicket");
			if(ticket != null && !ticket.equals("")){
				writerFile(ticket);
				logger.info(COMPONENT_APPID + ";推送component_verify_ticket协议-----------ticket = "+ticket);
			}
		} catch (DocumentException e) {
			e.printStackTrace();
		}
    }
    
    public void checkWeixinAllNetworkCheck(HttpServletRequest request, HttpServletResponse response,String xml) throws DocumentException, IOException, AesException{
        String nonce = request.getParameter("nonce");
        String timestamp = request.getParameter("timestamp");
        String msgSignature = request.getParameter("msg_signature");
 
        logger.info("自动检查，获取callback.." + msgSignature + " | " + timestamp+ " | " + nonce);
        WXBizMsgCrypt pc = new WXBizMsgCrypt(COMPONENT_TOKEN, COMPONENT_ENCODINGAESKEY, COMPONENT_APPID);
        xml = pc.decryptMsg(msgSignature, timestamp, nonce, xml);
 
        Document doc = DocumentHelper.parseText(xml);
        Element rootElt = doc.getRootElement();
        String msgType = rootElt.elementText("MsgType");
        String toUserName = rootElt.elementText("ToUserName");
        String fromUserName = rootElt.elementText("FromUserName");
 
        if("event".equals(msgType)){
        	 logger.info("---全网发布接入检测-------------事件消息--------");
        	 String event = rootElt.elementText("Event");
	         replyEventMessage(request,response,event,toUserName,fromUserName);
        }else if("text".equals(msgType)){
        	 logger.info("---全网发布接入检测-------------文本消息--------");
        	 String content = rootElt.elementText("Content");
	         processTextMessage(request,response,content,toUserName,fromUserName);
        }
    }
    
    public void replyEventMessage(HttpServletRequest request, HttpServletResponse response, String event, String toUserName, String fromUserName) throws DocumentException, IOException {
        String content = event + "from_callback";
        //---全网发布接入检测-------------事件回复消息  content="+content + "toUserName="+toUserName+"fromUserName="+fromUserName
        replyTextMessage(request,response,content,toUserName,fromUserName);
    }
    
    public void processTextMessage(HttpServletRequest request, HttpServletResponse response,String content,String toUserName, String fromUserName) throws IOException, DocumentException{
        if("TESTCOMPONENT_MSG_TYPE_TEXT".equals(content)){
            String returnContent = content+"_callback";
            replyTextMessage(request,response,returnContent,toUserName,fromUserName);
        }else if(StringUtils.startsWithIgnoreCase(content, "QUERY_AUTH_CODE")){
            output(response, "");
            //接下来客服API再回复一次消息
            replyApiTextMessage(request,response,content.split(":")[1],fromUserName);
        }
    }
    
    public void replyApiTextMessage(HttpServletRequest request, HttpServletResponse response, String auth_code, String fromUserName) throws DocumentException, IOException {
        String authorization_code = auth_code;
        // 得到微信授权成功的消息后，应该立刻进行处理！！相关信息只会在首次授权的时候推送过来
        logger.info("------step.1----使用客服消息接口回复粉丝----逻辑开始-------------------------");
        try {
        	ApiComponentToken apiComponentToken = new ApiComponentToken();
        	apiComponentToken.setComponent_appid(COMPONENT_APPID);
        	apiComponentToken.setComponent_appsecret(COMPONENT_APPSECRET);
        	String ticket = readFile();
        	apiComponentToken.setComponent_verify_ticket(ticket);
        	String component_access_token = JwThirdAPI.getAccessToken(apiComponentToken);
        	
        	logger.info("------step.2----使用客服消息接口回复粉丝------- component_access_token = "+component_access_token + "---------authorization_code = "+authorization_code);
        	net.sf.json.JSONObject authorizationInfoJson = JwThirdAPI.getApiQueryAuthInfo(COMPONENT_APPID, authorization_code, component_access_token);
        	logger.info("------step.3----使用客服消息接口回复粉丝-------------- 获取authorizationInfoJson = "+authorizationInfoJson);
        	net.sf.json.JSONObject infoJson = authorizationInfoJson.getJSONObject("authorization_info");
        	String authorizer_access_token = infoJson.getString("authorizer_access_token");
        	
        	
        	Map<String,Object> obj = new HashMap<String,Object>();
        	Map<String,Object> msgMap = new HashMap<String,Object>();
        	String msg = auth_code + "_from_api";
        	msgMap.put("content", msg);
        	
        	obj.put("touser", fromUserName);
        	obj.put("msgtype", "text");
        	obj.put("text", msgMap);
        	JwThirdAPI.sendMessage(obj, authorizer_access_token);
		} catch (WexinReqException e) {
			e.printStackTrace();
		}
        
    }
    
    /**
     * 写入文件
     * @param str
     */
    public void writerFile(String str){
    	try {
			File writename = new File(FILE); // 相对路径，如果没有则要建立一个新的output。txt文件  
			writename.createNewFile(); // 创建新文件  
			BufferedWriter out = new BufferedWriter(new FileWriter(writename));  
			out.write(str); // \r\n即为换行  
			out.flush(); // 把缓存区内容压入文件  
			out.close(); // 最后记得关闭文件  
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    /**
     * 读取文件
     */
    public static String readFile(){
    	try {
			File filename = new File(FILE); // 要读取以上路径的input。txt文件  
			// 建立一个输入流对象reader
			InputStreamReader reader = new InputStreamReader(new FileInputStream(filename));   
			BufferedReader br = new BufferedReader(reader); // 建立一个对象，它把文件内容转成计算机能读懂的语言  
			String line = br.readLine();  
			
			return line;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;  
    }
    
    /**
     * 判断是否加密
     * @param token
     * @param signature
     * @param timestamp
     * @param nonce
     * @return
     */
    public static boolean checkSignature(String token,String signature,String timestamp,String nonce){
        System.out.println("###token:"+token+";signature:"+signature+";timestamp:"+timestamp+"nonce:"+nonce);
    	   boolean flag = false;
    	   if(signature!=null && !signature.equals("") && timestamp!=null && !timestamp.equals("") && nonce!=null && !nonce.equals("")){
    	      String sha1 = "";
    	      String[] ss = new String[] { token, timestamp, nonce }; 
              Arrays.sort(ss);  
              for (String s : ss) {  
               sha1 += s;  
              }  
     
              sha1 = AddSHA1.SHA1(sha1);  
     
              if (sha1.equals(signature)){
        	   flag = true;
              }
    	   }
    	   return flag;
    }
    
    /**
     * 回复微信服务器"文本消息"
     * @param request
     * @param response
     * @param content
     * @param toUserName
     * @param fromUserName
     * @throws DocumentException
     * @throws IOException
     */
    public void replyTextMessage(HttpServletRequest request, HttpServletResponse response, String content, String toUserName, String fromUserName) throws DocumentException, IOException {
        Long createTime = Calendar.getInstance().getTimeInMillis() / 1000;
        StringBuffer sb = new StringBuffer();
        sb.append("<xml>");
		sb.append("<ToUserName><![CDATA["+fromUserName+"]]></ToUserName>");
		sb.append("<FromUserName><![CDATA["+toUserName+"]]></FromUserName>");
		sb.append("<CreateTime>"+createTime+"</CreateTime>");
		sb.append("<MsgType><![CDATA[text]]></MsgType>");
		sb.append("<Content><![CDATA["+content+"]]></Content>");
		sb.append("</xml>");
		String replyMsg = sb.toString();
        
        String returnvaleue = "";
        try {
            WXBizMsgCrypt pc = new WXBizMsgCrypt(COMPONENT_TOKEN, COMPONENT_ENCODINGAESKEY, COMPONENT_APPID);
            returnvaleue = pc.encryptMsg(replyMsg, createTime.toString(), "easemob");
        } catch (AesException e) {
            e.printStackTrace();
        }
        output(response, returnvaleue);
    }
    
    /**
     * 工具类：回复微信服务器"文本消息"
     * @param response
     * @param returnvaleue
     */
    public void output(HttpServletResponse response,String returnvaleue){
		try {
			PrintWriter pw = response.getWriter();
			pw.write(returnvaleue);
			pw.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
}
