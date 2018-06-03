package cn.chouchou;

import javax.jws.WebService;

@WebService
public interface IXiaomiSign {
   String sign(String datas);
   
   
   String signNew(String url,String sid,String salt,String datas);
   
   String privosionKeyUpload(String xmBase64key,String content);
   
   
   String  keyDownload(String xmBase64key,String fid,String clientData,String keyType,String aaid);
   

}
