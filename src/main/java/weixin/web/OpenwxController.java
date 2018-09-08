package weixin.web;

import org.apache.commons.lang.StringUtils;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
//import org.jeecgframework.core.util.LogUtil;
//import org.jeecgframework.core.util.ResourceUtil;
//import org.jeecgframework.core.util.oConvertUtils;
//import org.jeecgframework.web.system.service.SystemService;
import org.jeewx.api.core.exception.WexinReqException;
import org.jeewx.api.core.util.DateUtils;
import org.jeewx.api.mp.aes.AesException;
import org.jeewx.api.mp.aes.WXBizMsgCrypt;
import org.jeewx.api.third.JwThirdAPI;
import org.jeewx.api.third.model.ApiComponentToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import weixin.log.CommonLogFactory;
import weixin.log.CommonLogger;
import weixin.open.entity.base.WeixinOpenAccountEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * 微信公众账号第三方平台全网发布源码（java）
 * @author： jeewx开源社区
 * @网址：www.jeewx.com
 * @论坛：www.jeecg.org
 * @date 20150801
 */
@Controller
@RequestMapping("/openwx")
public class OpenwxController {

    //自动化测试的专用测试公众号appid
	private final String APPID = "wx570bc396a51b8ff8";
	//自动化测试的专用测试公众号 username
    private final String USERNAME = "gh_3c884a361561";
    private static CommonLogger logger = CommonLogFactory.getLogger(OpenwxController.class);

	//金科平方平台APPID
	private final static String COMPONENT_APPID = "wx5fc3967fdf9de618";
	//金科开放平台appsecret
	private final static String COMPONENT_APPSECRET = "b8ecd40b98e28929a6d001ae89bafeb3";
	//金科开放平台消息加解密key
	private final static String COMPONENT_ENCODINGAESKEY = "ryj8otghsh46jl895e6ujk68o4w5ygjtuk8w6htk5t6";
	//金科开放平台消息校验TOKEN
	private final static String COMPONENT_TOKEN = "34g31qgv3425g35";
	
//	@Autowired
//	private SystemService systemService;
	
	 /**
     * 授权事件接收
     * 
     * @param request
     * @param response
     * @throws IOException
     * @throws AesException
     * @throws DocumentException
     */
    @RequestMapping(value = "/event/authorize")
    public void acceptAuthorizeEvent(HttpServletRequest request, HttpServletResponse response) throws IOException, AesException, DocumentException {
        /**
         * 出于安全考虑，在第三方平台创建审核通过后，微信服务器 每隔10分钟会向第三方的消息接收地址推送一次component_verify_ticket，用于获取第三方平台接口调用凭据。
         */
        logger.info("微信第三方平台---------微信推送Ticket消息10分钟一次-----------" + DateUtils.gettimestamp().toString());
    	 processAuthorizeEvent(request);
         output(response, "success"); // 输出响应的内容。
    }
    
    @RequestMapping(value = "/authorCallback")
    public void authorCallback(HttpServletRequest request, HttpServletResponse response) throws IOException, AesException, DocumentException {
    	String auth_code = request.getParameter("auth_code");
    	String expires_in = request.getParameter("auth_code");
    	
    }
    
    
    /*
     * 一键授权功能
     * @param request
     * @param response
     * @throws IOException
     * @throws AesException
     * @throws DocumentException
     */
    @RequestMapping(value = "/goAuthor")
    public void goAuthor(HttpServletRequest request, HttpServletResponse response) throws IOException, AesException, DocumentException {
    	ApiComponentToken apiComponentToken = new ApiComponentToken();
    	apiComponentToken.setComponent_appid(COMPONENT_APPID);
    	apiComponentToken.setComponent_appsecret(COMPONENT_APPSECRET);
    	WeixinOpenAccountEntity  entity = getWeixinOpenAccount(APPID);
    	apiComponentToken.setComponent_verify_ticket(entity.getTicket());
    	try {
    	    //使用component_verify_ticket来获取component_access_token
			String component_access_token = JwThirdAPI.getAccessToken(apiComponentToken);
			//预授权码  第三方平台通过自己的接口调用凭据（component_access_token）来获取用于授权流程准备的预授权码（pre_auth_code）
			String preAuthCode = JwThirdAPI.getPreAuthCode(COMPONENT_APPID, component_access_token);
			String url = "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid="+COMPONENT_APPID+"&pre_auth_code="+preAuthCode+"&redirect_uri=";//+ResourceUtil.getConfigByName("domain")+"/rest/openwx/authorCallback";
			response.sendRedirect(url);
		} catch (WexinReqException e) {
			e.printStackTrace();
		}
    	
    }

    /**
     * 接受配置在第三方平台的request 消息与事件接收URL
     * http://ziencheng.com/openwx/$APPID$/callback
     * @param request
     * @param response
     * @throws IOException
     * @throws AesException
     * @throws DocumentException
     */
    @RequestMapping(value = "{appid}/callback")
    public void acceptMessageAndEvent(HttpServletRequest request, HttpServletResponse response) throws IOException, AesException, DocumentException {
        String msgSignature = request.getParameter("msg_signature");
        logger.info("第三方平台全网发布-------------{appid}/callback-----------验证开始。。。。msg_signature="+msgSignature);
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
        /**
         * <xml>
         *     <ToUserName><![CDATA[gh_3c884a361561]]></ToUserName>
         *     <Encrypt><![CDATA[m64gIdqDfmJWFym1nJDD/hHinEIttbjeAeqrwKYGSUs8h1jQNYzv8EogoKt+A1slDKvNBwa2YEWZZsfJcg7YeClLUBRPoIHHDQDhm8Re3F1CXRMQgyNHly5umvQ4/Yq3rQrq8YCpi3n3ErjTd5xhNiA/p4h3oNFTxD8fE9EU+tUary/RkTKvl/M2eBGPEa575MUWlUx45V9axtzLIXeSIHV0WkjUYLt3ijvYntUBEkLhm/D0DxBbGiaTTO6XDn8JpWg0XY1xg4mzZ2OfL/UppLrwHhG7V3lSS/6+AneMEiaM8ErfS9JQ9CPiffH04chgSqyZpMYyP77sYFOYhrVLl6XSo2M7NrRNMtsc//gw2hHqBPyPlkI2EW0u2/XCiQbdYDg9Agdl8RCjcSP8h03D1Bqpk020IxVIHCHdj9EJRLiL+6fcMvEDaoEr0LR7FOnJoZbhsU1gEnUFrlZctaDRirescwA1aSI/gLCXTDXFI84b4VafPPZwmQDkndJwsPX+dSBr8PdCDllldWciG0n+su7kyVfEIrz6JhrliCEJPJN/3JYHPi7uoFH6KFSVvf8JIF/pG+Qbb/a51ZK/8FUFmlQ==]]>
         *     </Encrypt>
         *</xml>
         */
        logger.info("第三方平台全网发布-------------{appid}/callback-----------验证开始。。。。xml="+xml);
        Document doc = DocumentHelper.parseText(xml);
        Element rootElt = doc.getRootElement();
        String toUserName = rootElt.elementText("ToUserName");
 
        //微信全网测试账号
        if (StringUtils.equalsIgnoreCase(toUserName, USERNAME)) {
           logger.info("全网发布接入检测消息反馈开始---------------APPID="+ APPID +"------------------------toUserName="+toUserName);
           checkWeixinAllNetworkCheck(request,response,xml);
        }
    }
    
    /*
     * 处理授权事件的推送
     * 
     * @param request
     * @throws IOException
     * @throws AesException
     * @throws DocumentException
     */
    public void processAuthorizeEvent(HttpServletRequest request) throws IOException, DocumentException, AesException {
        String nonce = request.getParameter("nonce");
        String timestamp = request.getParameter("timestamp");
        String signature = request.getParameter("signature");
        String msgSignature = request.getParameter("msg_signature");
 
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
            /**
             * 原始报文类似这样
             * <xml>
             *     <AppId><![CDATA[wx5fc3967fdf9de618]]></AppId>
             *     <Encrypt><![CDATA[2vkIc7Ri8OlbDU7AwYRlho5eKmquos3EQQ6JVHCCbnSjlDqTDXpTTXCMiTFQ2qvZYCJlWfy+GhHgYnn
             * 4ilR1TVC5tThevepOvv2LA4wNoQdGoZNdQT+yQ/c6aj5E+aGnQhQMTNK8xmRLyl67CeQeCf5UsrPKEsFGqxbZmmWL2m3aKbZgtsl27P94Mq8slT9K13fbpD9ubkHQEyGB8UmrTt+brlsW8U0QYz9mkfe8xSM2JRDdU4ZjW4WsIzoJq3+SPEBlK+TtxSQoZN+JqUqsIIg7CZSerOBc3OZV4ogIFvn6l8wCeh7uQmZjMVcW3hyFXcisBA6bsa7LNADjWS8A31MOwlzUrbobr0DMDT7qMnlAug+2SKTYubwQdJB5HUEz/imhhPVCy6nCMOGnzSXY3YG0O+eM7eErJm6h3a8lrZ2hwgSdu1STCH44hrIbAUb4GSMtoZIS4yaxGljBKzy/gOkJkUk7q4fy48oHpG3sw7Ox14YMH/aPQ0DGnC49rzVLBygNqGkusY9Gr6xoiyYwUMIfQPDed65JrI07hZt+T0UYyR0QULtedMMUhAqFZKoLdr3twj8vKkUtuojSWt2UssT7z5PGD58Zv5DElK2MLZS2FiAdVaQXwhdUWn3ArEekXcZ7+ed99KxlFdkcHQLefjysHV2tPL6dAnyl6EYLE1nq//TIlAD+55kcLyQFRIQfTkX3B5dpXrKMt6TcV/Lf2D/7CjsAIRz8vStHy8ww6wwVXzgWGEhJAci5rOnwE6KHafzhCKU4lpYDeNG31r+rYowmnbOEqibEkkwMNDcZjfFM=]]>
             *     </Encrypt>
             * </xml>
             */
            logger.info("第三方平台全网发布-----------------------原始 Xml="+xml);
            String encodingAesKey = COMPONENT_ENCODINGAESKEY;// 第三方平台组件加密密钥
            String appId = getAuthorizerAppidFromXml(xml);// 此时加密的xml数据中ToUserName是非加密的，解析xml获取即可
            logger.info("第三方平台全网发布-------------appid----------getAuthorizerAppidFromXml(xml)-----------appId="+appId);
            WXBizMsgCrypt pc = new WXBizMsgCrypt(COMPONENT_TOKEN, encodingAesKey, COMPONENT_APPID);
            xml = pc.decryptMsg(msgSignature, timestamp, nonce, xml);
            logger.info("第三方平台全网发布-----------------------解密后 Xml="+xml);

            processAuthorizationEvent(xml);
        }
    }
    
    /*
     * 保存Ticket
     * @param xml
     */
    void processAuthorizationEvent(String xml){
        /**
         * 解密后报文类似这样
         * //第三方平台appid
         <xml><AppId><![CDATA[wx5fc3967fdf9de618]]></AppId>
         <CreateTime>1536328643</CreateTime>
         <InfoType><![CDATA[component_verify_ticket]]></InfoType>
         <ComponentVerifyTicket>
         <![CDATA[ticket@@@6LTwQzSBzIMksx9GZIqb5o77ar-hp6-8_yKjJBsbATW3lgWI1J0cHeJ-SV3C-wPi15vjPsuBQRbo_9DkYrxJQw]]>
         </ComponentVerifyTicket>
         </xml>
         */
        /**
         * 微信官方文档写到：
         * 注意：
         * component_verify_ticket的有效时间较component_access_token更长，
         * 建议保存最近可用的component_verify_ticket，在component_access_token过期之前使用该ticket进行更新，
         * 避免出现因为ticket接收失败而无法更新component_access_token的情况。
         */
    	Document doc;
		try {
			doc = DocumentHelper.parseText(xml);
			Element rootElt = doc.getRootElement();
			String ticket = rootElt.elementText("ComponentVerifyTicket");
			if(StringUtils.isNotEmpty(ticket)){
			    logger.info("8、推送component_verify_ticket协议-----------ticket = \"+ticket)");
				WeixinOpenAccountEntity  entity = getWeixinOpenAccount(APPID);//这里的a
//				entity = entity==null?new WeixinOpenAccountEntity():entity;
				entity.setTicket(ticket);
				entity.setAppid(APPID);
				entity.setGetTicketTime(new Date());
//				systemService.saveOrUpdate(entity);
			}
		} catch (DocumentException e) {
			e.printStackTrace();
		}
    }
    
    /*
     * 获取授权账号信息
     * @param appid
     * @return
     */
    WeixinOpenAccountEntity getWeixinOpenAccount(String appid){
    	WeixinOpenAccountEntity  entity = null;
//		List<WeixinOpenAccountEntity> ls = systemService.findByProperty(WeixinOpenAccountEntity.class, "appid", appid);
//		if(ls!=null && ls.size()!=0){
//			 entity = ls.get(0);
//		}
		return entity;
    }
    
    /*
     * 获取授权的Appid
     * @param xml
     * @return
     */
	String getAuthorizerAppidFromXml(String xml) {
		Document doc;
		try {
			doc = DocumentHelper.parseText(xml);
			Element rootElt = doc.getRootElement();
			String appId = rootElt.elementText("AppId");
			return appId;
		} catch (DocumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
   
    
    public void checkWeixinAllNetworkCheck(HttpServletRequest request, HttpServletResponse response,String xml) throws DocumentException, IOException, AesException{
        String nonce = request.getParameter("nonce");
        String timestamp = request.getParameter("timestamp");
        String msgSignature = request.getParameter("msg_signature");
 
        WXBizMsgCrypt pc = new WXBizMsgCrypt(COMPONENT_TOKEN, COMPONENT_ENCODINGAESKEY, COMPONENT_APPID);
        xml = pc.decryptMsg(msgSignature, timestamp, nonce, xml);
 
        Document doc = DocumentHelper.parseText(xml);
        Element rootElt = doc.getRootElement();
        String msgType = rootElt.elementText("MsgType");
        String toUserName = rootElt.elementText("ToUserName");
        String fromUserName = rootElt.elementText("FromUserName");
 
        logger.info("---全网发布接入检测--step.1-----------msgType="+msgType+"-----------------toUserName="+toUserName+"-----------------fromUserName="+fromUserName);
        logger.info("---全网发布接入检测--step.2-----------xml="+xml);
        if("event".equals(msgType)){
        	 logger.info("---全网发布接入检测--step.3-----------事件消息--------");
        	 String event = rootElt.elementText("Event");
	         replyEventMessage(request,response,event,toUserName,fromUserName);
        }else if("text".equals(msgType)){
            /**
             * 类似这种报文
             * <xml><ToUserName><![CDATA[gh_3c884a361561]]></ToUserName>
             * <FromUserName><![CDATA[ozy4qt5QUADNXORxCVipKMV9dss0]]></FromUserName>
             * <CreateTime>1536320605</CreateTime>
             * <MsgType><![CDATA[text]]></MsgType>
             * <Content><![CDATA[TESTCOMPONENT_MSG_TYPE_TEXT]]></Content>
             * <MsgId>6598446755053214075</MsgId>
             * </xml>
             *
             * or
             *
             * <xml><ToUserName><![CDATA[gh_3c884a361561]]></ToUserName>
             * <FromUserName><![CDATA[ozy4qt5QUADNXORxCVipKMV9dss0]]></FromUserName>
             * <CreateTime>1536328596</CreateTime>
             * <MsgType><![CDATA[text]]></MsgType>
             * <Content><![CDATA[QUERY_AUTH_CODE:queryauthcode@@@7kOyFlKErMmS1G47yMFHuE7m_BLywiPJNGYxRyfQ09b8YqFu46ULpbIaE9T3tzY91B6SidBU0SQB9NHEmXpfVw]]></Content>
             * <MsgId>6598481076136876634</MsgId>
             * </xml>
             */
        	 logger.info("---全网发布接入检测--step.3-----------文本消息--------");
        	 String content = rootElt.elementText("Content");
	         processTextMessage(request,response,content,toUserName,fromUserName);
        }
    }
    
    
    public void replyEventMessage(HttpServletRequest request, HttpServletResponse response, String event, String toUserName, String fromUserName) throws DocumentException, IOException {
        String content = event + "from_callback";
        logger.info("---全网发布接入检测------step.4-------事件回复消息  content="+content + "   toUserName="+toUserName+"   fromUserName="+fromUserName);
        replyTextMessage(request,response,content,toUserName,fromUserName);
    }
 
    public void processTextMessage(HttpServletRequest request, HttpServletResponse response,String content,String toUserName, String fromUserName) throws IOException, DocumentException{
        if("TESTCOMPONENT_MSG_TYPE_TEXT".equals(content)){
            /**
             * 1、模拟粉丝发送文本消息给专用测试公众号，第三方平台方需根据文本消息的内容进行相应的响应：
             *
             * 1）微信模推送给第三方平台方：文本消息，其中Content字段的内容固定为：TESTCOMPONENT_MSG_TYPE_TEXT
             *
             * 2）第三方平台方立马回应文本消息并最终触达粉丝：Content必须固定为：TESTCOMPONENT_MSG_TYPE_TEXT_callback
             */
            String returnContent = content+"_callback";
            replyTextMessage(request,response,returnContent,toUserName,fromUserName);
        }else if(StringUtils.startsWithIgnoreCase(content, "QUERY_AUTH_CODE")){
            /**
             * 模拟粉丝发送文本消息给专用测试公众号，第三方平台方需在5秒内返回空串表明暂时不回复，然后再立即使用客服消息接口发送消息回复粉丝
             */
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
        	WeixinOpenAccountEntity  entity = getWeixinOpenAccount(APPID);
        	apiComponentToken.setComponent_verify_ticket(entity.getTicket());
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
    
    /*
     * 验证是否过期
     * @param accessTokenExpires
     * @return
     */
    boolean isExpired(long accessTokenExpires){
		return false;
    }
    
    /*
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
            logger.info("------------------加密后的返回内容 returnvaleue： "+returnvaleue);
        } catch (AesException e) {
            e.printStackTrace();
        }
        output(response, returnvaleue);
    }
    
    
//    public static void main(String[] args) {
//    	 Long createTime = Calendar.getInstance().getTimeInMillis() / 1000;
//    	 String replyMsg = "LOCATIONfrom_callback";
//
//         String returnvaleue = "";
//         try {
//             WXBizMsgCrypt pc = new WXBizMsgCrypt(COMPONENT_TOKEN, COMPONENT_ENCODINGAESKEY, COMPONENT_APPID);
//             returnvaleue = pc.encryptMsg(replyMsg, createTime.toString(), "easemob");
//             logger.info(returnvaleue);
//         } catch (AesException e) {
//             e.printStackTrace();
//         }
//	}
    /*
     * 工具类：回复微信服务器"文本消息"
     * @param response
     * @param returnvaleue
     */
    public void output(HttpServletResponse response,String returnvaleue){
		try {
			PrintWriter pw = response.getWriter();
			pw.write(returnvaleue);
			logger.info("****************returnvaleue***************="+returnvaleue);
			pw.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    /*
     * 判断是否加密
     * @param token
     * @param signature
     * @param timestamp
     * @param nonce
     * @return
     */
    public static boolean checkSignature(String token,String signature,String timestamp,String nonce){
        logger.info("###token:"+token+";signature:"+signature+";timestamp:"+timestamp+"nonce:"+nonce);
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
}


/*class AddSHA1 {
    public static String SHA1(String inStr) {
        MessageDigest md = null;
        String outStr = null;
        try {
            md = MessageDigest.getInstance("SHA-1");     //选择SHA-1，也可以选择MD5
            byte[] digest = md.digest(inStr.getBytes());       //返回的是byet[]，要转化为String存储比较方便
            outStr = bytetoString(digest);
        }
        catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        }
        return outStr;
    }
    
    
    public static String bytetoString(byte[] digest) {
        String str = "";
        String tempStr = "";
        
        for (int i = 0; i < digest.length; i++) {
            tempStr = (Integer.toHexString(digest[i] & 0xff));
            if (tempStr.length() == 1) {
                str = str + "0" + tempStr;
            }
            else {
                str = str + tempStr;
            }
        }
        return str.toLowerCase();
    }
}*/
