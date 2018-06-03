package cn.chouchou;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import net.sf.json.JSONObject;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.Test;



public class XiaomiSign implements IXiaomiSign {

	public String sign(String datas) {
		// TODO Auto-generated method stub
		/**
		 * 1、前台传入string必须截断成所需data
		 * 2、用httpclient技术发起一个post json 请求
		 * 3、获取返回的base64的string 转成能识别的给前台
		 * 需要jar包  sha1加密工具类common/codec  json工具类 httpclient类
		 * 
		 * 正确返回应该如下：
		 * {result:devPubKeyModulus:xxx\ndevPubKeyExponent:10001\ndevPubKeySign:xxx\ncriticalData:xxx\ncrticalDataSign:xxx"
                + ",code: 0}
		 * 
		 * 现将NV防篡改项目正式的sid和salt发给你们，请注意保密，不要分发给跟本项目研发无关的人员，谢谢！
			sid：N8xuvb4aUssplkDYf91oFZy2BO427583
			salt:bA5KmQr2E5wkCrDUfJKHBx2NqY6hqfLGw78gXtWeXoGfGj36viriPy9W5qJnpUlw
		 * */
		String result="";
		try{
			result=httpPostWithJSON(datas);
		}catch(Exception  e){
			e.printStackTrace();
		}
		return result;
	}
	
	
	/**
	 * xiaomi demo  data包括如下：
	 *  deviceDataObj.put("product", "cactus");
        deviceDataObj.put("cpuId", "1234567887654321");
        deviceDataObj.put("imei1", "862337021346120");
        deviceDataObj.put("imei2", "862337021355402");
        deviceDataObj.put("meid", "12345678654324");
        deviceDataObj.put("wifiMac", "0ESD23RF4Y3K");
        deviceDataObj.put("btMac", "0B66785T7D53");
        deviceDataObj.put("emmcId", "01234567899");                          // emmc id. adb shell cat /sys/class/block/mmcblk0/device/serial
        deviceDataObj.put("ufsId", "0123456789");                            // ufs id. adb shell cat /d/ufshcd0/dump_string_desc_serial
        deviceDataObj.put("fpUid", "00000000-00000000-00000000-00");
	 *   
	 *  防止不同语言间  ws调用出错   参数用String传递  
	 * */
	private  String httpPostWithJSON(String datas) throws Exception {
        String url="https://protect.dev.sec.miui.com/factory/encrypt/deviceInfo";  //小米 正式环境web 服务地址
		//String url="https://staging.protect.dev.sec.miui.com/factory/encrypt/deviceInfo";
        HttpPost httpPost = new HttpPost(url);
        CloseableHttpClient client = HttpClients.createDefault();
        
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        
        String respContent = null;
        
        /**
         * request 部分：https post  json:
         * sid
         * data
         * nonce
         * timestamp
         * sign
         * 
         * */
        
        String sid = "miFactory1";// N8xuvb4aUssplkDYf91oFZy2BO427583小米公司  提供miFactory1
        String salt = "MetbItDqQICkzOdwyoszDbcseoE5V2Nw";//bA5KmQr2E5wkCrDUfJKHBx2NqY6hqfLGw78gXtWeXoGfGj36viriPy9W5qJnpUlw MetbItDqQICkzOdwyoszDbcseoE5V2Nw
        long timestamp = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
       //data 部分  必须json base64加密
        JSONObject deviceDataObj = new JSONObject();
        String[] paras=datas.split(";");
        for(String s:paras){
        	String[] sigle_para=s.split("=");
        	deviceDataObj.put(sigle_para[0], sigle_para[1]);
        	nvps.add(new BasicNameValuePair(sigle_para[0], sigle_para[1]));
        }
        String encodedFlashData = Base64.encodeBase64String(deviceDataObj.toString().getBytes());
        String joinedStr = new StringBuilder().append("POST\n").append("/factory/encrypt/deviceInfo\n").append("data=").append(encodedFlashData)
                .append("&nonce=").append(nonce).append("&sid=").append(sid).append("&timestamp=").append(timestamp).toString();
        String sign = HmacUtils.hmacSha1Hex(salt, joinedStr);
        
        
        //小米写法  不清楚内容是form传统表单提交还是内部有json转化  按文档的json请求 进行请求
        //RequestBody formBody = new FormEncodingBuilder().add("sid", sid).add("data", encodedFlashData).add("nonce", nonce).add("sign", sign).build();
        //Request deviceProtectRequest = new Request.Builder().url("https://protect.dev.sec.miui.com/factory/encrypt/deviceInfo").post(formBody).build();
        /**
         * json 请求
         * 
        JSONObject   request_json=new JSONObject();
        request_json.put("sid", sid);
        request_json.put("data", encodedFlashData);
        request_json.put("nonce", nonce);
        request_json.put("timestamp", timestamp);
        request_json.put("sign", sign);
        
        
        StringEntity entity = new StringEntity(request_json.toString(),"utf-8");//解决中文乱码问题    
        entity.setContentEncoding("UTF-8");    
        entity.setContentType("application/json");    
        httpPost.setEntity(entity);
        System.out.println(request_json.toString());
        */
        
        //传统表单
      
		//设置参数到请求对象中
		httpPost.setEntity(new UrlEncodedFormEntity(nvps, "utf-8"));
		System.out.println("请求地址："+url);
		System.out.println("请求参数："+nvps.toString());
		
		//设置header信息
		//指定报文头【Content-type】、【User-Agent】
		httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
		httpPost.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
		
		
        
        
        HttpResponse resp = client.execute(httpPost);
        if(resp.getStatusLine().getStatusCode() == 200) {
            HttpEntity he = resp.getEntity();
            respContent = EntityUtils.toString(he,"UTF-8");
            respContent=new String(Base64.decodeBase64(respContent),"utf-8");
        }
        else{
        	  JSONObject  failMessage=new JSONObject();
        	  failMessage.put("you input", nvps.toString());
        	  failMessage.put("message", "xiaomi web response code not 200");
        	  respContent=failMessage.toString();
        }
        return respContent;
    }
	
	
	
    //sign=5ffca02bba90cc237523f50340ef4111e87fb4a4
	@Test
	public  void test(){
		    String sid = "miFactory1";
	        String salt = "MetbItDqQICkzOdwyoszDbcseoE5V2Nw";
	        long timestamp = System.currentTimeMillis();//System.currentTimeMillis() 1521536575879L
	        String nonce =UUID.randomUUID().toString();// UUID.randomUUID().toString(); 0244e823-2872-45df-8439-3b823a36a204
	       //data 部分  必须json base64加密
	        JSONObject deviceDataObj = new JSONObject();
	       
		    deviceDataObj.put("product", "sirius");//cactus
	        deviceDataObj.put("cpuId", "1234567887654321");
	        deviceDataObj.put("imei1", "862337021346120");
	        deviceDataObj.put("imei2", "862337021355402");
	        deviceDataObj.put("meid", "12345678654324");
	        deviceDataObj.put("wifiMac", "0ESD23RF4Y3K");
	        deviceDataObj.put("btMac", "0B66785T7D53");
	        deviceDataObj.put("emmcId", "01234567899");                          // emmc id. adb shell cat /sys/class/block/mmcblk0/device/serial
	        deviceDataObj.put("ufsId", "0123456789");                            // ufs id. adb shell cat /d/ufshcd0/dump_string_desc_serial
	        deviceDataObj.put("fpUid", "00000000-00000000-00000000-00");         // Fingerprint uid.  adb shell getprop persist.sys.fp.uid
	        
	       
	        /***
	        deviceDataObj.put("btMac", "0B66785T7D53");
	        deviceDataObj.put("cpuId", "1234567887654321");
	        deviceDataObj.put("emmcId", "01234567899");                          // emmc id. adb shell cat /sys/class/block/mmcblk0/device/serial
	        deviceDataObj.put("fpUid", "00000000-00000000-00000000-00");         // Fingerprint uid.  adb shell getprop persist.sys.fp.uid
	        deviceDataObj.put("imei1", "862337021346120");
	        deviceDataObj.put("imei2", "862337021355402");
	        deviceDataObj.put("meid", "12345678654324");
		    deviceDataObj.put("product", "cactus");
		    deviceDataObj.put("ufsId", "0123456789");                            // ufs id. adb shell cat /d/ufshcd0/dump_string_desc_serial
	        deviceDataObj.put("wifiMac", "0ESD23RF4Y3K");
	       */
	        
	        String encodedFlashData = Base64.encodeBase64String(deviceDataObj.toString().getBytes());
	        //logger.debug("deviceDataObjData= {}", deviceDataObj);

	        String joinedStr = new StringBuilder().append("POST\n").append("/factory/encrypt/deviceInfo\n").append("data=").append(encodedFlashData)
	                .append("&nonce=").append(nonce).append("&sid=").append(sid).append("&timestamp=").append(timestamp).toString();
	        String sign = HmacUtils.hmacSha1Hex(salt, joinedStr);
	       
	        //request json
	        
	      /*  JSONObject   request_json=new JSONObject();
	        request_json.put("sid", sid);
	        request_json.put("data", encodedFlashData);
	        request_json.put("nonce", nonce);
	        request_json.put("timestamp", timestamp);
	        request_json.put("sign", sign);
	        System.out.println(request_json);*/
	        
	        String request_str="sid="+sid+"&data="+encodedFlashData+"&nonce="+nonce+"&timestamp="+timestamp+"&sign="+sign;
	        System.out.println(request_str);
	        
	        //sid=miFactory1&sign=905e3397748e36e4eaf55d42fb76f66ce3ae54e5&timestamp=1521536138064&nonce=f86bb5e2-ad74-4843-a4c2-803f95cd34bf&data=eyJwcm9kdWN0IjoiY2FjdHVzIiwiY3B1SWQiOiIxMjM0NTY3ODg3NjU0MzIxIiwiaW1laTEiOiI4NjIzMzcwMjEzNDYxMjAiLCJpbWVpMiI6Ijg2MjMzNzAyMTM1NTQwMiIsIm1laWQiOiIxMjM0NTY3ODY1NDMyNCIsIndpZmlNYWMiOiIwRVNEMjNSRjRZM0siLCJidE1hYyI6IjBCNjY3ODVUN0Q1MyIsImVtbWNJZCI6IjAxMjM0NTY3ODk5IiwidWZzSWQiOiIwMTIzNDU2Nzg5IiwiZnBVaWQiOiIwMDAwMDAwMC0wMDAwMDAwMC0wMDAwMDAwMC0wMCJ9&=
	          //sid=miFactory1&sign=e3cb741693995634a021e45214d16ae24830339b&timestamp=1521591301223&noce=797e4c5d-da1f-427c-80e3-57db0d8ec292&data=eyJidE1hYyI6IjBCNjY3ODVUN0Q1MyIsImNwdUlkIjoiMTIzNDU2Nzg4NzY1NDMyMSIsImVtbWNJZCI6IjAxMjM0NTY3ODk5IiwiZnBVaWQiOiIwMDAwMDAwMC0wMDAwMDAwMC0wMDAwMDAwMC0wMCIsImltZWkxIjoiODYyMzM3MDIxMzQ2MTIwIiwiaW1laTIiOiI4NjIzMzcwMjEzNTU0MDIiLCJtZWlkIjoiMTIzNDU2Nzg2NTQzMjQiLCJwcm9kdWN0IjoiY2FjdHVzIiwidWZzSWQiOiIwMTIzNDU2Nzg5Iiwid2lmaU1hYyI6IjBFU0QyM1JGNFkzSyJ9
	        //eyJwcm9kdWN0IjoiY2FjdHVzIiwiY3B1SWQiOiIxMjM0NTY3ODg3NjU0MzIxIiwiaW1laTEiOiI4NjIzMzcwMjEzNDYxMjAiLCJpbWVpMiI6Ijg2MjMzNzAyMTM1NTQwMiIsIm1laWQiOiIxMjM0NTY3ODY1NDMyNCIsIndpZmlNYWMiOiIwRVNEMjNSRjRZM0siLCJidE1hYyI6IjBCNjY3ODVUN0Q1MyIsImVtbWNJZCI6IjAxMjM0NTY3ODk5IiwidWZzSWQiOiIwMTIzNDU2Nzg5IiwiZnBVaWQiOiIwMDAwMDAwMC0wMDAwMDAwMC0wMDAwMDAwMC0wMCJ9;
	}
	
	

	
	
  
	//下面防止SSL安全密匙的影响
	
	public  SSLContext createIgnoreVerifySSL() throws NoSuchAlgorithmException, KeyManagementException {  
	    SSLContext sc = SSLContext.getInstance("SSLv3");  
	  
	    // 实现一个X509TrustManager接口，用于绕过验证，不用修改里面的方法  
	    X509TrustManager trustManager = new X509TrustManager() {  
	        public void checkClientTrusted(  
	                java.security.cert.X509Certificate[] paramArrayOfX509Certificate,  
	                String paramString) throws CertificateException {  
	        }  
	  
	        public void checkServerTrusted(  
	                java.security.cert.X509Certificate[] paramArrayOfX509Certificate,  
	                String paramString) throws CertificateException {  
	        }  
	  
	        public java.security.cert.X509Certificate[] getAcceptedIssuers() {  
	            return null;  
	        }  
	    };  
	  
	    sc.init(null, new TrustManager[] { trustManager }, null);  
	    return sc;  
	}  
	
	//发送json请求的格式
	public  String sendjson(String url, String datas,String encoding) throws KeyManagementException, NoSuchAlgorithmException, ClientProtocolException, IOException {
		String body = "";
		//采用绕过验证的方式处理https请求
		SSLContext sslcontext = createIgnoreVerifySSL();
		
        // 设置协议http和https对应的处理socket链接工厂的对象
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
            .register("http", PlainConnectionSocketFactory.INSTANCE)
            .register("https", new SSLConnectionSocketFactory(sslcontext))
            .build();
        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        HttpClients.custom().setConnectionManager(connManager);

        //创建自定义的httpclient对象
		CloseableHttpClient client = HttpClients.custom().setConnectionManager(connManager).build();
//		CloseableHttpClient client = HttpClients.createDefault();
		
		//创建post方式请求对象
		HttpPost httpPost = new HttpPost(url);
		
		
		
		
		
		  
        String sid = "N8xuvb4aUssplkDYf91oFZy2BO427583";//小米公司  提供
        String salt = "bA5KmQr2E5wkCrDUfJKHBx2NqY6hqfLGw78gXtWeXoGfGj36viriPy9W5qJnpUlw";
        long timestamp = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
       //data 部分  必须json base64加密
        JSONObject deviceDataObj = new JSONObject();
        String[] paras=datas.split(";");
        for(String s:paras){
        	String[] sigle_para=s.split("=");
        	deviceDataObj.put(sigle_para[0], sigle_para[1]);
        }
        String encodedFlashData = Base64.encodeBase64String(deviceDataObj.toString().getBytes());
        String joinedStr = new StringBuilder().append("POST\n").append("/factory/encrypt/deviceInfo\n").append("data=").append(encodedFlashData)
                .append("&nonce=").append(nonce).append("&sid=").append(sid).toString();
        String sign = HmacUtils.hmacSha1Hex(salt, joinedStr);
		
        
        JSONObject   request_json=new JSONObject();
        request_json.put("sid", sid);
        request_json.put("data", encodedFlashData);
        request_json.put("nonce", nonce);
        request_json.put("timestamp", timestamp);
        request_json.put("sign", sign);
        
        
        StringEntity request_entity = new StringEntity(request_json.toString(),"utf-8");//解决中文乱码问题  
        httpPost.setEntity(request_entity);
	
		//设置header信息
		//指定报文头【Content-type】、【User-Agent】
		httpPost.setHeader("Content-type", "application/json");
		httpPost.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
		
		//执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response = client.execute(httpPost);
		//获取结果实体
		HttpEntity entity = response.getEntity();
		if (entity != null) {
			//按指定编码转换结果实体为String类型
			body = EntityUtils.toString(entity, encoding);
		}
		EntityUtils.consume(entity);
		//释放链接
		response.close();
        return body;
	}
    
	
	/**
	传统表单的提交方式
	 */
	public  String send(String url, Map<String,String> map,String encoding) throws KeyManagementException, NoSuchAlgorithmException, ClientProtocolException, IOException {
		String body = "";
		//采用绕过验证的方式处理https请求
		SSLContext sslcontext = createIgnoreVerifySSL();
		
        // 设置协议http和https对应的处理socket链接工厂的对象
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
            .register("http", PlainConnectionSocketFactory.INSTANCE)
            .register("https", new SSLConnectionSocketFactory(sslcontext))
            .build();
        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        HttpClients.custom().setConnectionManager(connManager);

        //创建自定义的httpclient对象
		CloseableHttpClient client = HttpClients.custom().setConnectionManager(connManager).build();
//		CloseableHttpClient client = HttpClients.createDefault();
		
		//创建post方式请求对象
		HttpPost httpPost = new HttpPost(url);
		
		//装填参数
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		if(map!=null){
			for (Entry<String, String> entry : map.entrySet()) {
				nvps.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
			}
		}
		//设置参数到请求对象中
		httpPost.setEntity(new UrlEncodedFormEntity(nvps, encoding));

		System.out.println("请求地址："+url);
		System.out.println("请求参数："+nvps.toString());
		
		//设置header信息
		//指定报文头【Content-type】、【User-Agent】
		httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
		httpPost.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
		
		//执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response = client.execute(httpPost);
		//获取结果实体
		HttpEntity entity = response.getEntity();
		if (entity != null) {
			//按指定编码转换结果实体为String类型
			body = EntityUtils.toString(entity, encoding);
		}
		EntityUtils.consume(entity);
		//释放链接
		response.close();
        return body;
	}
	

	
	 @Test
	 public  void  testsend(){
		Map<String, String>  map=new HashMap<String, String>();
		map.put("sid", "N8xuvb4aUssplkDYf91oFZy2BO427583");
		map.put("data", "eyJwcm9kdWN0IjoiY2FjdHVzIiwiY3B1SWQiOiIxMjM0NTY3ODg3NjU0MzIxIiwiaW1laTEiOiI4NjIzMzcwMjEzNDYxMjAiLCJpbWVpMiI6Ijg2MjMzNzAyMTM1NTQwMiIsIm1laWQiOiIxMjM0NTY3ODY1NDMyNCIsIndpZmlNYWMiOiIwRVNEMjNSRjRZM0siLCJidE1hYyI6IjBCNjY3ODVUN0Q1MyIsImVtbWNJZCI6IjAxMjM0NTY3ODk5IiwidWZzSWQiOiIwMTIzNDU2Nzg5IiwiZnBVaWQiOiIwMDAwMDAwMC0wMDAwMDAwMC0wMDAwMDAwMC0wMCJ9");
		map.put("nonce", "d6ec26c0-2a1c-47da-88e5-7639a5a22f9d");
		map.put("timestamp", "1521525248502");
		map.put("sign", "a46e427d8e99e3979fdc9f907cc46a8edb2a8e4c");
		String res=null;
		 try {
			 res=send("https://protect.dev.sec.miui.com/factory/encrypt/deviceInfo",map,"utf-8");
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 System.out.println(res);
	 }
	 
	 
	 
	/* deviceDataObj.put("product", "cactus");
     deviceDataObj.put("cpuId", "1234567887654321");
     deviceDataObj.put("imei1", "862337021346120");
     deviceDataObj.put("imei2", "862337021355402");
     deviceDataObj.put("meid", "12345678654324");
     deviceDataObj.put("wifiMac", "0ESD23RF4Y3K");
     deviceDataObj.put("btMac", "0B66785T7D53");
     deviceDataObj.put("emmcId", "01234567899");                          // emmc id. adb shell cat /sys/class/block/mmcblk0/device/serial
     deviceDataObj.put("ufsId", "0123456789");                            // ufs id. adb shell cat /d/ufshcd0/dump_string_desc_serial
     deviceDataObj.put("fpUid", "00000000-00000000-00000000-00");*/
	 @Test
	 public  void  testsendjson(){
		Map<String, String>  map=new HashMap<String, String>();
		map.put("sid", "N8xuvb4aUssplkDYf91oFZy2BO427583");
		map.put("data", "eyJwcm9kdWN0IjoiY2FjdHVzIiwiY3B1SWQiOiIxMjM0NTY3ODg3NjU0MzIxIiwiaW1laTEiOiI4NjIzMzcwMjEzNDYxMjAiLCJpbWVpMiI6Ijg2MjMzNzAyMTM1NTQwMiIsIm1laWQiOiIxMjM0NTY3ODY1NDMyNCIsIndpZmlNYWMiOiIwRVNEMjNSRjRZM0siLCJidE1hYyI6IjBCNjY3ODVUN0Q1MyIsImVtbWNJZCI6IjAxMjM0NTY3ODk5IiwidWZzSWQiOiIwMTIzNDU2Nzg5IiwiZnBVaWQiOiIwMDAwMDAwMC0wMDAwMDAwMC0wMDAwMDAwMC0wMCJ9");
		map.put("nonce", "d6ec26c0-2a1c-47da-88e5-7639a5a22f9d");
		map.put("timestamp", "1521525248502");
		map.put("sign", "a46e427d8e99e3979fdc9f907cc46a8edb2a8e4c");
		String res=null;
		 try {
			 res=sendjson("https://protect.dev.sec.miui.com/factory/encrypt/deviceInfo","product=cactus;cpuId=1234567887654321;","utf-8");
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 System.out.println(res);
	 }
  
	 
	//.......................................................................................................

	public String signNew(String url, String sid, String salt, String datas) {
		// TODO Auto-generated method stub
		String result="";
		try{
			result=httpPost(url,sid,salt,datas);
		}catch(Exception  e){
			e.printStackTrace();
		}
		return result;
	}
	
	private  String httpPost(String url, String sid, String salt, String datas) throws Exception {
        //String url="https://protect.dev.sec.miui.com/factory/encrypt/deviceInfo";  //小米 正式环境web 服务地址
		//String url="https://staging.protect.dev.sec.miui.com/factory/encrypt/deviceInfo";
        HttpPost httpPost = new HttpPost(url);
        CloseableHttpClient client = HttpClients.createDefault();
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        String respContent = null;
        /**
         * request 部分：https post  json:
         * sid
         * data
         * nonce
         * timestamp
         * sign
         * 
         * */
        
       // String sid = "miFactory1";// N8xuvb4aUssplkDYf91oFZy2BO427583小米公司  提供miFactory1
        //String salt = "MetbItDqQICkzOdwyoszDbcseoE5V2Nw";//bA5KmQr2E5wkCrDUfJKHBx2NqY6hqfLGw78gXtWeXoGfGj36viriPy9W5qJnpUlw MetbItDqQICkzOdwyoszDbcseoE5V2Nw
        long timestamp = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
       //data 部分  必须json base64加密
        JSONObject deviceDataObj = new JSONObject();
        String[] paras=datas.split(";");
        for(String s:paras){
        	String[] sigle_para=s.split("=");
        	deviceDataObj.put(sigle_para[0], sigle_para[1]);
        	
        }
        String encodedFlashData = Base64.encodeBase64String(deviceDataObj.toString().getBytes());
        String joinedStr = new StringBuilder().append("POST\n").append("/factory/encrypt/deviceInfo\n").append("data=").append(encodedFlashData)
                .append("&nonce=").append(nonce).append("&sid=").append(sid).append("&timestamp=").append(timestamp).toString();
        String sign = HmacUtils.hmacSha1Hex(salt, joinedStr);
        
        nvps.add(new  BasicNameValuePair("sid", sid));
        nvps.add(new  BasicNameValuePair("data", encodedFlashData));
        nvps.add(new  BasicNameValuePair("timestamp", timestamp+""));
        nvps.add(new  BasicNameValuePair("sign", sign));
        nvps.add(new  BasicNameValuePair("nonce", nonce));
        
        //传统表单
      
		//设置参数到请求对象中
		httpPost.setEntity(new UrlEncodedFormEntity(nvps, "utf-8"));
		System.out.println("请求地址："+url);
		System.out.println("请求参数："+nvps.toString());
		
		//设置header信息
		//指定报文头【Content-type】、【User-Agent】
		httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
		httpPost.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
		
		
        
        
        HttpResponse resp = client.execute(httpPost);
        if(resp.getStatusLine().getStatusCode() == 200) {
            HttpEntity he = resp.getEntity();
            respContent = EntityUtils.toString(he,"UTF-8");
            respContent=new String(Base64.decodeBase64(respContent),"utf-8");
        }
        else{
        	  JSONObject  failMessage=new JSONObject();
        	  failMessage.put("you input", nvps.toString());
        	  failMessage.put("message", "xiaomi web response code not 200");
        	  respContent=failMessage.toString();
        }
        return respContent;
    }
	
	@Test
	public  void testsignNew(){
		String datas="product=sirius;cpuId=1234567887654321;imei1=862337021346120;imei2=862337021355402;meid=12345678654324;wifiMac=0ESD23RF4Y3K;btMac=0B66785T7D53;emmcId=01234567899;ufsId=0123456789;fpUid=00000000-00000000-00000000-00;";
		
		//String datas="product=cactus;cpuId=1234567887654321;imei1=862337021346120;imei2=862337021355402;meid=12345678654324;wifiMac=0ESD23RF4Y3K;" +
			//	"btMac=0B66785T7D53;emmcId=01234567899;ufsId=0123456789;fpUid=00000000-00000000-00000000-00;";
		String res=signNew(
				"https://protect.dev.sec.miui.com/factory/encrypt/deviceInfo", 
				"miFactory1", 
				"MetbItDqQICkzOdwyoszDbcseoE5V2Nw",
				datas);
		System.out.println(res);
	}

    /**
     * 小米provision  上传
     * 需要传入 key (key需要做base64解码)
     * content  原始数据 需要做base64编码
     * */
	public String privosionKeyUpload(String xmBase64key, String content){
		// TODO Auto-generated method stub
		//小米公司根据每个IP 分发的 需要小米提供
		//String base64key_xm="Rrgg22XgM4HJFsjC5huhAL+aw3YriXOdL65XUPIcBvoSTt7vmKovMVl74Rrvg/v+hFGw1FA4admyrRN8DSm16SjrG+tbohjURU6oMOubugqxE8YzRg0qydERBiKQk6s11jTYLgmZTyDTQ3/mqx8sNonO6n/U57LdnQuF+f9tYCp2Pla8gkhF9rFy4KPci40nVsTANHhX7gNWzTGlxnN3L8Uexrh3RMI7NpfKBareBXojyXOUpZHMrdfcFnS9v6gjUBFJKUMOOK+vw2gzDiAUY33gg99cfttIb+c8yLJIE3PhvD6Popy+Pci01zWaTO4QoDQ1o8FdI5XTNaTJLjxJRg==";
		byte[] key_xm=Base64.decodeBase64(xmBase64key);
		
		content=Base64.encodeBase64String(content.getBytes());
		//小米content  demo
		//content="UFJPSkVDVCxTTk8sQ1VTVE9NRVJTTixDUFVfSUQsSU1FSSxJTUVJMixNRUlELFBST1ZJU0lPTixLUEgsU1VJRApIM1osMk01NDdGMDAxMTU0LDEyMTk0LzIwMDAwMDQwLDY4MDg5MjIwMDYwMjYwZjUwMDAwMDAwMDAwMDAwMDAwLDg2ODAyOTAyNjAyMDA2NSwsLEFRQUFBSHdEQUFBaUFBQUFVQUlBQUNRQUFBQUFBUUFBQmhONG8zemxaLzlQRis3ZlhxR0hZM3dHdVpCMlVrMndRYm5EdTZuQ0N0SmpqUlhXK05pT2JNUXExUzdBQmlVS29UUjhqbFRtSWIzeG5sa3pINk52cmdSeVBJQ0dDQkRtdWt0anJSd0pzbCtVYjkvMnpJRTlZQUk1YSsyOHRPVkdtamx6ajBtalFxWnZReGl3WFpBV3VFcjZYQTl6c1RKbGJpQ0M3QkxKVmtJaGZDSUcwQk1IOHRkbjdvcmJ5QzZWUWwzcHJhVTVKQWJZYUUwZ2VwVTlWS0tJSFhPaXoyS2tiTFNmL1BIemlUMUhtdmJyUk9jNk4rOU5DUzdtdmVOb1pzWjUwNUZwdkNidlREeGpXQWpKRDZENDhQSndXZUNSS2VMZWZ3c2RCR2crY1Y1NlUwaW94QzVOQXhiSkdmZ2p0QXFUdFNaVGVvVk1Xc1k2eWVzcTRDVUFBQUJBQVFBQXlwY3orSFNLZGVYWmZpUmtqdXdZNE9JeGFFdGpTMjRHSmVaVThHWHlKZElad21yd254Si90VlNYc1J0U2JOeWJRYlluOFJLWjdNUllmS2QycDB3cFhPc3c3aEtyWFVvcDU0dTZETzB5ZlhmckRFVEYwWjFhUVFscEdMK0RJK2VhdGR4ZkVUNDJvbnY4SE1mTGl2S0tpc1pmRXlKOVg0SHAvdVFFdkpPSzg5cDdIQmhEN3l5a1J3K3haT09hTHJ1VHIxWU5BdWdHU0Fha2RVTzB2YmxYQzFwUnBIR25IeFVXZHBKMS9MU1l3S2RXZEJkMzdKWjZGQUZHbVZNSGpZZTRDUE83T21LeDlkRVNBN2NPS3VEOTkvZWNacXlvRU04Y0hpejRUNDEveHA3NkR2RVk1RDhNMGtXZzJMNUU0ZFppYjc0Tmp1Skc1dkxocUFsN2Y4TEhNb1lIN0VBSXJJVGJLUUxtbk5qOTZyYk1HY3lYR2JnU3JyRWxOVEVIT1FYOVpuNzBKQlN2OHJTOTlvekMzQmdNdTRtSU1pMXJPSDFYM241aHp4d3VwKzRqQUFBQUlBQUFBTzk1ZmlwUnZ6UlE2NWI0cUMzRkl4by9YQi9jTmJ6elk3ckpGaWRocTNjZUtRQUFBT3dBQUFCbmFHbHZOR2hQY25oeE9ISTVTVWROV21rMVRGZ3ZNMFJyY3pCS04xVnlOVE42TlhOSlJ6WnpOV05STDJkcFp6TmtVR2hqTlVoWWJGQnlaRzA0Um1wbllYZG1hRlVyTUdKaE5GazRXR3BHWm00emIyd3ZRV0ZHT1d4ek5WVlVORlUyY2xsbmRHNXJlRkUyT1VGTlYxWmhOV1Z1VkRsbmJsaFZVR2x4UzBKNk5XTm1RVmhETkZVMmJuWXdhMUZvWmxKTFdXbFRiR05EVVZwalEzSkhibFZMVDBwWlZVZFdNVVZxUTNoTE5UWXJTRzFMZFVwck5tOHZWRWhRTUZSSVNWUmxRbEpxU3pKb1pXcE5SbEpvWkZJMVoyd3pNVnA2Y0ZvMWJGUkVUbkpTV0dkT2VsYzJSSEZqU1RkSlBRPT0kM0VlTVZTaVZMZytwK0owQ0xRSFBkSVlNSEZCRVczZWdZempsalRFTE9lYz0sMTc4ZTM0NzViODAyZTMwMzVmMGRmZGZjYzQwZDViZGMzNDAyZWMwZjg3NzEyNGExZGRlYWY5YzFjY2Y3OTRkZWVlZDljMmNjNTgyNjc4NWUwNWU5ZmNiOTgyMzEwNzA2YzUxYzIzODI3MmVkNTcxZjI5MGVkNGE3ZTM0MTZmYmExMWZjNmYzOTY5Mzg1NjA1NjE0OGNlMTQzM2Q4NzY4MDRiY2VlNGVmN2M4MzBmNzlmMjEzMmZlZWM0YTEzN2VjNDVhNWU3Zjc4MjI3ZmFlOTg0NmQ2YzUzMzkxZjQ0YjRhZjAxYjY5MTRkYWM5NWZiZDVjNjFmYTM3YzE3M2FjZWNkYjVhYzAwNmUyMGIxOTY0YmZhOTZlNWJjZTZhODY5NTk5N2Q3NWE2MmU1NGI2NDBhMDRhOWIxMWQzM2M3ODVmYTFmNzY0ZTFhYWY1MjFhMWQxZTBkMjgyMmIzOTljZDhhMDdjM2JkNDBjNzlhMjNhYWEyNzlkMjk5NzEyZmQ5OGZlNWI4YzAzMmZiYzE2ZjNmYmYyYjFlMWVmNTU5Y2M3ZWE3NGIyNGUyZmJkODc4MzRhZjhhNzFhMzJhYmVhNjgzYjgyMmZkYWEzZjQ0Y2E1MDJhYWE0MzQyMTI3M2FiZDUyNTUyYTViOWI5MzMzN2UzNjIzODM2MmQxOGU3ZjgzNjdkZTIzYWNlZDM0NDBlNDA0N2E3MTJjNWU4ZTBkZGNiMTY3ZDZiMmZhOWFiZDgzOGNjY2I5ZGI4OTQ0N2I2YjgyYTcxMDA0MjdjZGNkOWNiNjQ2MjI3N2ZjZTA0ZmE2MjZkZjNhZGY0OGMzYzFmNGJmMGY5MDlkOGM0NzU4YzIzYjMyY2Y1NTJjZGE1Y2YwNzg4OGNjOWVkZTI3YjVlMGE1Y2NhMGY0Y2Q2OGM1YTU2ZDhlMDkwOWY5MWNiOGIwZjdmMDI0ZjFmZGNhYzY3MzU0ZjAyZWRlYjgyOTNhYmM0ZTllMjBjMTE5OTg2YTUzNjhhY2UzN2M4Y2Q1NzAwYzc3YjE3MDVjNDdiNTQ1NGI1Mzg4NzNhYTNhYTVlMDgzNzAwNDI3YzNlMGFjM2Y1YThjMzUyNzEyMGM5MGY1Zjg3MzZkN2VhMTEwMDQ0M2FhOTdlMTljNDQxODVmMWNhNmVkMjAzMWVjNDMwMDMyYjg0ODU5ZWJhNWM0YmFiYmNiMjU1OTEzNzIxNTU5MmM1ZGRhZjFmMGI5MjI5YzY0NDUxZDkxYjExOTBlNzAwODU0YzA1MWE1NDUwMzE1YzIwZjYxY2M0MDQwMDBhYjEwMDgwYjAyOGUwMmVkNWI0NTBhM2MwY2QyNmMzYTQ5OTRlMDNlZmRkMWI0ZTU5ZjUyZCwwOTAwMDAwMDk1NjcwMDAwZTk1NWVkM2YxZTg0OTNkNA==";
		byte[] sign_byte=HmacUtils.hmacSha256(key_xm, content.getBytes());
		String sign_final=Base64.encodeBase64String(sign_byte);
		System.out.println(sign_final);
		
		HttpPost httpPost = new HttpPost("https://i.mi.com/support/anonymous/provision");
        CloseableHttpClient client = HttpClients.createDefault();
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        String respContent = null;
		
        
        
        nvps.add(new  BasicNameValuePair("base64Sign", sign_final));
        nvps.add(new  BasicNameValuePair("base64Content", content));
      
        
        //传统表单
      
		//设置参数到请求对象中
        try{
			httpPost.setEntity(new UrlEncodedFormEntity(nvps, "utf-8"));
			System.out.println("请求参数："+nvps.toString());
			
			//设置header信息
			//指定报文头【Content-type】、【User-Agent】
			httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
			httpPost.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
			
			
	        
	        
	        HttpResponse resp = client.execute(httpPost);
	        if(resp.getStatusLine().getStatusCode() == 200) {
	            HttpEntity he = resp.getEntity();
	            respContent = EntityUtils.toString(he,"UTF-8");
	            
	        }
	        else{
	        	  JSONObject  failMessage=new JSONObject();
	        	  failMessage.put("you input", nvps.toString());
	        	  failMessage.put("message", "xiaomi web response code not 200");
	        	  respContent=failMessage.toString();
	        }
	    }
        catch(Exception  e){
        	
        }
        return respContent;
		
	}
	
	
	
	@Test
	public  void  testprivosionKeyUpload(){
		String xmBase64key="Rrgg22XgM4HJFsjC5huhAL+aw3YriXOdL65XUPIcBvoSTt7vmKovMVl74Rrvg/v+hFGw1FA4admyrRN8DSm16SjrG+tbohjURU6oMOubugqxE8YzRg0qydERBiKQk6s11jTYLgmZTyDTQ3/mqx8sNonO6n/U57LdnQuF+f9tYCp2Pla8gkhF9rFy4KPci40nVsTANHhX7gNWzTGlxnN3L8Uexrh3RMI7NpfKBareBXojyXOUpZHMrdfcFnS9v6gjUBFJKUMOOK+vw2gzDiAUY33gg99cfttIb+c8yLJIE3PhvD6Popy+Pci01zWaTO4QoDQ1o8FdI5XTNaTJLjxJRg==";
		String content="PROJECT,SNO,CUSTOMERSN,CPU_ID,IMEI,IMEI2,MEID,PROVISION,KPH,SUID\nH3Z,2M547F001154,12194/20000040,68089220060260f50000000000000000,868029026020065,,,AQAAAHwDAAAiAAAAUAIAACQAAAAAAQAABhN4o3zlZ/9PF+7fXqGHY3wGuZB2Uk2wQbnDu6nCCtJjjRXW+NiObMQq1S7ABiUKoTR8jlTmIb3xnlkzH6NvrgRyPICGCBDmuktjrRwJsl+Ub9/2zIE9YAI5a+28tOVGmjlzj0mjQqZvQxiwXZAWuEr6XA9zsTJlbiCC7BLJVkIhfCIG0BMH8tdn7orbyC6VQl3praU5JAbYaE0gepU9VKKIHXOiz2KkbLSf/PHziT1HmvbrROc6N+9NCS7mveNoZsZ505FpvCbvTDxjWAjJD6D48PJwWeCRKeLefwsdBGg+cV56U0ioxC5NAxbJGfgjtAqTtSZTeoVMWsY6yesq4CUAAABAAQAAypcz+HSKdeXZfiRkjuwY4OIxaEtjS24GJeZU8GXyJdIZwmrwnxJ/tVSXsRtSbNybQbYn8RKZ7MRYfKd2p0wpXOsw7hKrXUop54u6DO0yfXfrDETF0Z1aQQlpGL+DI+eatdxfET42onv8HMfLivKKisZfEyJ9X4Hp/uQEvJOK89p7HBhD7yykRw+xZOOaLruTr1YNAugGSAakdUO0vblXC1pRpHGnHxUWdpJ1/LSYwKdWdBd37JZ6FAFGmVMHjYe4CPO7OmKx9dESA7cOKuD99/ecZqyoEM8cHiz4T41/xp76DvEY5D8M0kWg2L5E4dZib74NjuJG5vLhqAl7f8LHMoYH7EAIrITbKQLmnNj96rbMGcyXGbgSrrElNTEHOQX9Zn70JBSv8rS99ozC3BgMu4mIMi1rOH1X3n5hzxwup+4jAAAAIAAAAO95fipRvzRQ65b4qC3FIxo/XB/cNbzzY7rJFidhq3ceKQAAAOwAAABnaGlvNGhPcnhxOHI5SUdNWmk1TFgvM0RrczBKN1VyNTN6NXNJRzZzNWNRL2dpZzNkUGhjNUhYbFByZG04RmpnYXdmaFUrMGJhNFk4WGpGZm4zb2wvQWFGOWxzNVVUNFU2cllndG5reFE2OUFNV1ZhNWVuVDlnblhVUGlxS0J6NWNmQVhDNFU2bnYwa1FoZlJLWWlTbGNDUVpjQ3JHblVLT0pZVUdWMUVqQ3hLNTYrSG1LdUprNm8vVEhQMFRISVRlQlJqSzJoZWpNRlJoZFI1Z2wzMVp6cFo1bFRETnJSWGdOelc2RHFjSTdJPQ==$3EeMVSiVLg+p+J0CLQHPdIYMHFBEW3egYzjljTELOec=,178e3475b802e3035f0dfdfcc40d5bdc3402ec0f877124a1ddeaf9c1ccf794deeed9c2cc5826785e05e9fcb982310706c51c238272ed571f290ed4a7e3416fba11fc6f39693856056148ce1433d876804bcee4ef7c830f79f2132feec4a137ec45a5e7f78227fae9846d6c53391f44b4af01b6914dac95fbd5c61fa37c173acecdb5ac006e20b1964bfa96e5bce6a8695997d75a62e54b640a04a9b11d33c785fa1f764e1aaf521a1d1e0d2822b399cd8a07c3bd40c79a23aaa279d299712fd98fe5b8c032fbc16f3fbf2b1e1ef559cc7ea74b24e2fbd87834af8a71a32abea683b822fdaa3f44ca502aaa43421273abd52552a5b9b93337e36238362d18e7f8367de23aced3440e4047a712c5e8e0ddcb167d6b2fa9abd838cccb9db89447b6b82a7100427cdcd9cb6462277fce04fa626df3adf48c3c1f4bf0f909d8c4758c23b32cf552cda5cf07888cc9ede27b5e0a5cca0f4cd68c5a56d8e0909f91cb8b0f7f024f1fdcac67354f02edeb8293abc4e9e20c119986a5368ace37c8cd5700c77b1705c47b5454b538873aa3aa5e083700427c3e0ac3f5a8c3527120c90f5f8736d7ea1100443aa97e19c44185f1ca6ed2031ec430032b84859eba5c4babbcb2559137215592c5ddaf1f0b9229c64451d91b1190e700854c051a5450315c20f61cc404000ab10080b028e02ed5b450a3c0cd26c3a4994e03efdd1b4e59f52d,0900000095670000e955ed3f1e8493d4";
	   String res=privosionKeyUpload(xmBase64key, content);
	   System.out.println(res);
	}

     
	/**
	   fid: 设备fid
	   clientData: tz生成的加密数据，包含rsa public key，以及对他的签名（参考客⼾端：通过 TZ设备签名，下发⽀付宝/FIDO的private key）
	   keyType: 请求key类型，如果有多个，⽤逗号分割。⽐如："alipay,fido"
	   aaid: 可选参数，如果接⼝keyType中包含fido, aaid必须提供
	   base64Sign: 将“fid:keyType”(ASCII冒号字符连接的上述2个参数的字符串内容)⽤HMacSHA256Key做签名，然后将签名变成Base64 unchunked的字符串。 其中
	               HMacSHA256Key是根据IP 预先分配的1个Base64HMacSHA256Key，解Base64得到
	 */  
	
	public String keyDownload(String xmBase64key,String fid, String clientData, String keyType,
			String aaid) {
		// TODO Auto-generated method stub
        byte[] key_xm=Base64.decodeBase64(xmBase64key);
		String content=fid+":"+keyType; //不知道小米那边需不不要base64转码
		//小米content  demo
		//content="UFJPSkVDVCxTTk8sQ1VTVE9NRVJTTixDUFVfSUQsSU1FSSxJTUVJMixNRUlELFBST1ZJU0lPTixLUEgsU1VJRApIM1osMk01NDdGMDAxMTU0LDEyMTk0LzIwMDAwMDQwLDY4MDg5MjIwMDYwMjYwZjUwMDAwMDAwMDAwMDAwMDAwLDg2ODAyOTAyNjAyMDA2NSwsLEFRQUFBSHdEQUFBaUFBQUFVQUlBQUNRQUFBQUFBUUFBQmhONG8zemxaLzlQRis3ZlhxR0hZM3dHdVpCMlVrMndRYm5EdTZuQ0N0SmpqUlhXK05pT2JNUXExUzdBQmlVS29UUjhqbFRtSWIzeG5sa3pINk52cmdSeVBJQ0dDQkRtdWt0anJSd0pzbCtVYjkvMnpJRTlZQUk1YSsyOHRPVkdtamx6ajBtalFxWnZReGl3WFpBV3VFcjZYQTl6c1RKbGJpQ0M3QkxKVmtJaGZDSUcwQk1IOHRkbjdvcmJ5QzZWUWwzcHJhVTVKQWJZYUUwZ2VwVTlWS0tJSFhPaXoyS2tiTFNmL1BIemlUMUhtdmJyUk9jNk4rOU5DUzdtdmVOb1pzWjUwNUZwdkNidlREeGpXQWpKRDZENDhQSndXZUNSS2VMZWZ3c2RCR2crY1Y1NlUwaW94QzVOQXhiSkdmZ2p0QXFUdFNaVGVvVk1Xc1k2eWVzcTRDVUFBQUJBQVFBQXlwY3orSFNLZGVYWmZpUmtqdXdZNE9JeGFFdGpTMjRHSmVaVThHWHlKZElad21yd254Si90VlNYc1J0U2JOeWJRYlluOFJLWjdNUllmS2QycDB3cFhPc3c3aEtyWFVvcDU0dTZETzB5ZlhmckRFVEYwWjFhUVFscEdMK0RJK2VhdGR4ZkVUNDJvbnY4SE1mTGl2S0tpc1pmRXlKOVg0SHAvdVFFdkpPSzg5cDdIQmhEN3l5a1J3K3haT09hTHJ1VHIxWU5BdWdHU0Fha2RVTzB2YmxYQzFwUnBIR25IeFVXZHBKMS9MU1l3S2RXZEJkMzdKWjZGQUZHbVZNSGpZZTRDUE83T21LeDlkRVNBN2NPS3VEOTkvZWNacXlvRU04Y0hpejRUNDEveHA3NkR2RVk1RDhNMGtXZzJMNUU0ZFppYjc0Tmp1Skc1dkxocUFsN2Y4TEhNb1lIN0VBSXJJVGJLUUxtbk5qOTZyYk1HY3lYR2JnU3JyRWxOVEVIT1FYOVpuNzBKQlN2OHJTOTlvekMzQmdNdTRtSU1pMXJPSDFYM241aHp4d3VwKzRqQUFBQUlBQUFBTzk1ZmlwUnZ6UlE2NWI0cUMzRkl4by9YQi9jTmJ6elk3ckpGaWRocTNjZUtRQUFBT3dBQUFCbmFHbHZOR2hQY25oeE9ISTVTVWROV21rMVRGZ3ZNMFJyY3pCS04xVnlOVE42TlhOSlJ6WnpOV05STDJkcFp6TmtVR2hqTlVoWWJGQnlaRzA0Um1wbllYZG1hRlVyTUdKaE5GazRXR3BHWm00emIyd3ZRV0ZHT1d4ek5WVlVORlUyY2xsbmRHNXJlRkUyT1VGTlYxWmhOV1Z1VkRsbmJsaFZVR2x4UzBKNk5XTm1RVmhETkZVMmJuWXdhMUZvWmxKTFdXbFRiR05EVVZwalEzSkhibFZMVDBwWlZVZFdNVVZxUTNoTE5UWXJTRzFMZFVwck5tOHZWRWhRTUZSSVNWUmxRbEpxU3pKb1pXcE5SbEpvWkZJMVoyd3pNVnA2Y0ZvMWJGUkVUbkpTV0dkT2VsYzJSSEZqU1RkSlBRPT0kM0VlTVZTaVZMZytwK0owQ0xRSFBkSVlNSEZCRVczZWdZempsalRFTE9lYz0sMTc4ZTM0NzViODAyZTMwMzVmMGRmZGZjYzQwZDViZGMzNDAyZWMwZjg3NzEyNGExZGRlYWY5YzFjY2Y3OTRkZWVlZDljMmNjNTgyNjc4NWUwNWU5ZmNiOTgyMzEwNzA2YzUxYzIzODI3MmVkNTcxZjI5MGVkNGE3ZTM0MTZmYmExMWZjNmYzOTY5Mzg1NjA1NjE0OGNlMTQzM2Q4NzY4MDRiY2VlNGVmN2M4MzBmNzlmMjEzMmZlZWM0YTEzN2VjNDVhNWU3Zjc4MjI3ZmFlOTg0NmQ2YzUzMzkxZjQ0YjRhZjAxYjY5MTRkYWM5NWZiZDVjNjFmYTM3YzE3M2FjZWNkYjVhYzAwNmUyMGIxOTY0YmZhOTZlNWJjZTZhODY5NTk5N2Q3NWE2MmU1NGI2NDBhMDRhOWIxMWQzM2M3ODVmYTFmNzY0ZTFhYWY1MjFhMWQxZTBkMjgyMmIzOTljZDhhMDdjM2JkNDBjNzlhMjNhYWEyNzlkMjk5NzEyZmQ5OGZlNWI4YzAzMmZiYzE2ZjNmYmYyYjFlMWVmNTU5Y2M3ZWE3NGIyNGUyZmJkODc4MzRhZjhhNzFhMzJhYmVhNjgzYjgyMmZkYWEzZjQ0Y2E1MDJhYWE0MzQyMTI3M2FiZDUyNTUyYTViOWI5MzMzN2UzNjIzODM2MmQxOGU3ZjgzNjdkZTIzYWNlZDM0NDBlNDA0N2E3MTJjNWU4ZTBkZGNiMTY3ZDZiMmZhOWFiZDgzOGNjY2I5ZGI4OTQ0N2I2YjgyYTcxMDA0MjdjZGNkOWNiNjQ2MjI3N2ZjZTA0ZmE2MjZkZjNhZGY0OGMzYzFmNGJmMGY5MDlkOGM0NzU4YzIzYjMyY2Y1NTJjZGE1Y2YwNzg4OGNjOWVkZTI3YjVlMGE1Y2NhMGY0Y2Q2OGM1YTU2ZDhlMDkwOWY5MWNiOGIwZjdmMDI0ZjFmZGNhYzY3MzU0ZjAyZWRlYjgyOTNhYmM0ZTllMjBjMTE5OTg2YTUzNjhhY2UzN2M4Y2Q1NzAwYzc3YjE3MDVjNDdiNTQ1NGI1Mzg4NzNhYTNhYTVlMDgzNzAwNDI3YzNlMGFjM2Y1YThjMzUyNzEyMGM5MGY1Zjg3MzZkN2VhMTEwMDQ0M2FhOTdlMTljNDQxODVmMWNhNmVkMjAzMWVjNDMwMDMyYjg0ODU5ZWJhNWM0YmFiYmNiMjU1OTEzNzIxNTU5MmM1ZGRhZjFmMGI5MjI5YzY0NDUxZDkxYjExOTBlNzAwODU0YzA1MWE1NDUwMzE1YzIwZjYxY2M0MDQwMDBhYjEwMDgwYjAyOGUwMmVkNWI0NTBhM2MwY2QyNmMzYTQ5OTRlMDNlZmRkMWI0ZTU5ZjUyZCwwOTAwMDAwMDk1NjcwMDAwZTk1NWVkM2YxZTg0OTNkNA==";
		byte[] sign_byte=HmacUtils.hmacSha256(key_xm, content.getBytes());
		String sign_final=Base64.encodeBase64String(sign_byte);
		
		HttpPost httpPost = new HttpPost("https://i.mi.com/support/anonymous/externalkey");
        CloseableHttpClient client = HttpClients.createDefault();
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        String respContent = null;
		
        
        
        nvps.add(new  BasicNameValuePair("fid", fid));
        nvps.add(new  BasicNameValuePair("clientData", clientData));
        nvps.add(new  BasicNameValuePair("keyType", keyType));
        nvps.add(new  BasicNameValuePair("aaid", aaid));
        nvps.add(new  BasicNameValuePair("base64Sign", sign_final));
      
        
        //传统表单
      
		//设置参数到请求对象中
        try{
			httpPost.setEntity(new UrlEncodedFormEntity(nvps, "utf-8"));
			System.out.println("请求参数："+nvps.toString());
			
			//设置header信息
			//指定报文头【Content-type】、【User-Agent】
			httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
			httpPost.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
			
			
	        
	        
	        HttpResponse resp = client.execute(httpPost);
	        if(resp.getStatusLine().getStatusCode() == 200) {
	            HttpEntity he = resp.getEntity();
	            respContent = EntityUtils.toString(he,"UTF-8");
	            
	        }
	        else{
	        	  JSONObject  failMessage=new JSONObject();
	        	  failMessage.put("you input", nvps.toString());
	        	  failMessage.put("message", "xiaomi web response code not 200");
	        	  respContent=failMessage.toString();
	        }
	    }
        catch(Exception  e){
        	
        }
        return respContent;
	}
	
	
	@Test
	public  void  testkeyDownload(){
		String xmBase64key="Rrgg22XgM4HJFsjC5huhAL+aw3YriXOdL65XUPIcBvoSTt7vmKovMVl74Rrvg/v+hFGw1FA4admyrRN8DSm16SjrG+tbohjURU6oMOubugqxE8YzRg0qydERBiKQk6s11jTYLgmZTyDTQ3/mqx8sNonO6n/U57LdnQuF+f9tYCp2Pla8gkhF9rFy4KPci40nVsTANHhX7gNWzTGlxnN3L8Uexrh3RMI7NpfKBareBXojyXOUpZHMrdfcFnS9v6gjUBFJKUMOOK+vw2gzDiAUY33gg99cfttIb+c8yLJIE3PhvD6Popy+Pci01zWaTO4QoDQ1o8FdI5XTNaTJLjxJRg==";
	 String res=	keyDownload(xmBase64key, "fid", "PROJECT,SNO,CUSTOMERSN,CPU_ID,IMEI,IMEI2,MEID,PROVISION,KPH,SUID\nH3Z,2M547F001154,12194/20000040,68089220060260f50000000000000000,868029026020065,,,AQAAAHwDAAAiAAAAUAIAACQAAAAAAQAABhN4o3zlZ/9PF+7fXqGHY3wGuZB2Uk2wQ", "alipay", "");
	 System.out.println(res);
	}



	
	
}
