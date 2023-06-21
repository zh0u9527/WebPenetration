# 1. 前提知识

-   Socket编程；
-   IO流；



# 2. 思路

1.  启动Socket服务，循环接收浏览器请求；
2.  接收到请求之后，将流中的数据取出来；
3.  判断目标资源是否存在，若不存在则返回404；
4.  若存在，将目标资源通过输出流响应给客户端；



# 3. 相关类

-   Server：开启一个Socket服务
-   Request：封装请求，处理请求的相关业务；
-   Response：封装响应，处理响应的相关业务；
-   Test：测试类



# 4. 代码实现

## 4.1 WebServer.java

```java
package com.example;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * 启动Socket服务的主类。
 */
public class MyHttpServer {
    //服务器端口
    private final int port = 9999;

    //启动服务
    public void start(){
        try {
            ServerSocket server = new ServerSocket(port);
            //开始接收请求
            while (true){
                Socket socket = server.accept();
                //获取前端请求
                InputStream inputStream = socket.getInputStream();
                //响应请求请求
                OutputStream outputStream = socket.getOutputStream();
                //处理请求
                MyHttpRequest httpRequest = new MyHttpRequest(inputStream);
                String rui = httpRequest.parse();
                //响应请求
                MyHttpResponse myHttpResponse = new MyHttpResponse(outputStream);
                myHttpResponse.sendResponseResource(rui);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
```



## 4.2 HttpRequest.java

```java
package com.example;


import java.io.IOException;
import java.io.InputStream;

/**
 * 处理HttpRequest
 */
public class MyHttpRequest {
    //表示前端浏览器的请求输入流
    private InputStream inputStream;

    public MyHttpRequest() {
    }

    public MyHttpRequest(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    /**
     * 解析HttpRequest
     */
    protected String parse(){
        try {
            //读取HttpRequest请求数据
            byte[] buffer = new byte[inputStream.available()];
            inputStream.read(buffer);
            String requestString = new String(buffer);
            return getUri(requestString);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取http请求的uri
     * @param requestString 请求头（字符串）
     * @return 返回uri地址
     */
    private String getUri(String requestString){
        if (requestString.length() == 0)
            return "";
        //开始下标与结束下标
        int start, end;
        start = requestString.indexOf(' ');
        //注：这里的fromIndex是包含起始下标的，所以这里要start+1
        end = requestString.indexOf(' ', start+1);
        return requestString.substring(start+1, end);//去掉/方便后面的字符串拼接
    }
}
```



## 4.3 HttpResponse.java

```java
package com.example;

import java.io.*;

/**
 * HttpResponse对象
 */
public class MyHttpResponse {
    private OutputStream outputStream;

    public MyHttpResponse() {
    }

    public MyHttpResponse(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    protected void sendResponseResource(String uri){
        try {
            String responseMessage = responseMessage(uri);
            //将资源数据响应给浏览器
            this.outputStream.write(responseMessage.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String responseMessage(String uri){
        //资源是根目录
        if (uri.length() == 0 || "/".equals(uri)){
            uri="index.html";
        }
        //获取项目绝对路径
        String projectURL = System.getProperty("user.dir");
        //创建uri文件对象
        File file = new File(projectURL + "/WebResource/" + uri);
        if (file.exists()) {
            try {
                //资源存在
                //读取资源文件
                FileInputStream fileInputStream = new FileInputStream(file);
                byte[] buffer = new byte[fileInputStream.available()];
                fileInputStream.read(buffer);
                String fileContent = new String(buffer);
                return message("200", fileContent);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            String responseContent = "404 Not Found!";
            return message("404", responseContent);
        }
    }

    private String message(String responseCode, String responseBody){
        return "HTTP/1.1 "+responseCode+" \r\n" +
               "Content-Length: " + responseBody.length() + " \r\n" +
               "\r\n" + responseBody;
    }
}
```



## 4.4 Test.java

```java
package com.test;

import com.example.MyHttpServer;

public class MyTest {
    public static void main(String[] args) {
        System.out.println("Server startup...");
        MyHttpServer myHttpServer = new MyHttpServer();
        myHttpServer.start();
    }
}
```

