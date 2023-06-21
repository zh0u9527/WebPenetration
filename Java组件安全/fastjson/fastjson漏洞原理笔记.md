# 1. fastjson是什么？

fastjson是阿里巴巴的开源JSON解析库，它可以解析JSON格式的字符串，支持将Java Bean序列化为JSON字符串，也可以从JSON字符串反序列化到JavaBean。

参考：https://github.com/alibaba/fastjson/wiki/Quick-Start-CN



# 2. 基本使用

## 2.1 将json字符串转为json对象

```java
String s = "{\"param1\":\"aaa\",\"param2\":\"bbb\"}";
JSONObject jsonObject = JSON.parseObject(s);
System.out.println(jsonObject.get("param1")); // aaa
```



## 2.2 将json字符串转为Javabean

```java
String s1 = "{\"username\":\"zhang\",\"password\":\"zhang123\"}";
Person person = JSON.parseObject(s1, Person.class);
System.out.println(person);
/*
	输出：
		Person constructor
        setUsername() method
        setPassword() method
        Person{username='zhang', password='zhang123'}
*/
```



Person.java

```java
package com.fastjsonvul;

import java.util.Map;
import java.util.Objects;

public class Person {
    private String username;
    private String password;

    private Map<Objects, Objects> map;

    @Override
    public String toString() {
        return "Person{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}';
    }

    public String getUsername() {
        System.out.println("getUsername() method");
        return username;
    }

    public void setUsername(String username) {
        System.out.println("setUsername() method");
        this.username = username;
    }

    public String getPassword() {
        System.out.println("getPassword() method");
        return password;
    }

    public void setPassword(String password) {
        System.out.println("setPassword() method");
        this.password = password;
    }

    public Person() {
        System.out.println("Person constructor");
    }


    public Person(String username, String password) {
        this.username = username;
        this.password = password;
    }
     public Map<Objects, Objects> getMap(){
         System.out.println("getMap() method");
         return this.map;
     }
}
```



## 2.3 根据传入字符串的类型去解析json字符串

```java
String s2 = "{\"@type\":\"com.fastjsonvul.Person\",\"username\":\"zhangsan\",\"password\":\"zhangsan123\"}";
JSONObject jsonObject = JSON.parseObject(s2);
System.out.println(jsonObject);
/*
	输出：
		Person constructor
    setUsername() method
    setPassword() method
    getMap() method
    getPassword() method
    getUsername() method
    {"password":"zhangsan123","username":"zhangsan"}
*/
```



