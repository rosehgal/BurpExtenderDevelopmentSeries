# Deep Dive into Extender API Interface

So far we learned how to write a basic `Hello World` extension showcasing interaction with Burp Suite.

In this part of the series, we’ll mostly cover the Extender API interfaces and their use cases. In the Chapters end write will create an extension which will monitor HTTP requests from Burp Suite tools and display the domains passing through the Proxy in the Alert tab.

## tl;dr
In this chapter we will be covering:  
1. [Helper Interface](#helper-interface)
1. [Simple URL Encoder](#simple-url-encoder)
2. [Interface Registration](#interface-registration)
3. [Listen for events from Proxy](#listen-for-events-from-proxy)
3. [Code](../../code/BurpExtenderChapter3)

## Helper Interface

In the previous post. We used callbacks object’s methods twice for setting name of the extension and displaying a message on Alert tab. Callback interface is really great, it offers plenty of other resources as instance objects as well.

One of the important method exposed by callbacks is `getHelpers()`. This method returns an object of `IExtensionHelperstype`, which as the name suggests will be going to help us in making boring tasks easier. The object contains multiple methods such as:  
- `analyzeRequest()`: This method can be used to analyze an HTTP request, and obtain various key details about it.
- `analyzeResponse()`: This method can be used to analyze an HTTP response, and obtain various key details about it.
- `base64Encode()`: This method can be used to Base64-encode the specified data.
- `base64Decode()`: This method can be used to decode Base64-encoded data.
- `urlDecode()`: This method can be used to URL-decode the specified data.
- `urlEncode()`: This method can be used to URL-encode the specified data
- and many more. The full list of Extension helper can be found [here](https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html).

## Simple URL encoder
Let's create a very simple static URL encoder with the process that we have learnt so far. We will use the same process to create a base class which will receive a `IBurpExtenderInterface` as callback object, we will use to it get helper instance and eventually create a encoded string for static URL and display encoded text in `Alerts` tab.
Code is pretty straight forward and self explanatory.

```java
package burp;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("URL Encoder");

        // This is how we receive helper's object reference from callback instance.
        IExtensionHelpers helpers = callbacks.getHelpers();

        String encodedString = helpers.urlEncode("http://www.example.com/dir/path?q=10&a=100");
        callbacks.issueAlert(encodedString);   
    }
}

```

## Interface registration

In order to implement API interface of Extender meaningfully, it is required to call the `register*` method from the callback interface.

As an example if you are implementing `IHTTPListener` interface in any of the class object must have their objects passed to `callbacks.registerHttpListener()` method, for the actual interface to work properly.

Note that callbacks itself is an object of type `IBurpExtenderCallbacks`. `IntelliJ` loaded with interface file will show you suggestions something like this.

<p align=center>
<image src="../../static/images/chapter3/file1.png" width=90% />
</p>

Each API interface that you will implement will separate `register` method corresponding to it.

## Listen for Events from Proxy
Let's create a class which will implement `IHTTPListener` interface. The class will:
1. Listen for events from Burp Suite Proxy tab.
2. Class will be notified for `request` and `response` from Burp Proxy.
3. Class will log all the `request` in `Alerts` tab.

Create a class which will implement the `IHTTPListener` interface. In this interface we would need to implement `processHttpMessage` method.

Read the comments for explanation.

```java
/*
    LogProxyRequests.java
*/

package burp;

public class LogProxyRequests implements IHttpListener{

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private IExtensionHelpers iExtensionHelpers;

    public LogProxyRequests(IBurpExtenderCallbacks callbacks){
        /*
            For issuing alert to Alter tab.
         */
        iBurpExtenderCallbacks = callbacks;

        /*
            For parsing requests.
         */
        iExtensionHelpers = callbacks.getHelpers();
    }

    @Override public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = null;

        /*
            Only listen for events from Burp Suite proxy && Only listen for requests.
         */
        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && messageIsRequest == true)
            requestInfo = iExtensionHelpers.analyzeRequest(messageInfo);
            String domainName = requestInfo.getUrl().getHost();

            /*
                Log the domain name to Alerts tab.
             */
            iBurpExtenderCallbacks.issueAlert("Proxy: " + domainName);
    }
}

```

Register the implemented class in Our `BurpExtender.java` class file.
```java
/*
    BurpExtender.java
*/

package burp;

public class BurpExtender implements IBurpExtender{
    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Proxy Request Logger");
        callbacks.issueAlert("Extension loaded");

        /*
            Register our LogProxyRequest instance to burp suite proxy.
         */
        callbacks.registerHttpListener(new LogProxyRequests(callbacks));
    }
}
```
Build the jar and load the jar in Burp Suite. If everything goes well, you will domain names getting logged in alerts tab.

<p align=center>
<image src="../../static/images/chapter3/file2.png" width=90% />
</p>

### [Next Chapter: Understanding a use case - Intruder Payload processing](series/Chapter3/README.md)