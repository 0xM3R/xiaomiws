<%@ page language="java" import="java.util.*" pageEncoding="UTF-8"%>
<%
     String path=request.getContextPath();
      pageContext.setAttribute("path", path);
%>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    
    <title>My JSP 'index.jsp' starting page</title>
	<meta http-equiv="pragma" content="no-cache">
	<meta http-equiv="cache-control" content="no-cache">
	<meta http-equiv="expires" content="0">    
	<meta http-equiv="keywords" content="keyword1,keyword2,keyword3">
	<meta http-equiv="description" content="This is my page">
	<!--
	<link rel="stylesheet" type="text/css" href="styles.css">
	-->
  </head>
  
  <body>
               
  
                   <h1>如果您能看到这个页面,证明web服务是正常开启的</h1>
                   <a href="${path}/ws">请移步小米sign的 webservice</a>
                   
  </body>
</html>
